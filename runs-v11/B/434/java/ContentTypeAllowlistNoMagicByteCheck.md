## Verdict
exploitable

## Source
Line 32: `@RequestParam("file") MultipartFile file` - the uploaded file is attacker-controlled.

## Fix

**Library Recommendation**

Add Apache Tika to detect actual file content type from bytes:
```
org.apache.tika:tika-core
```
Version should be confirmed against current SCA/dependency-check tooling. Additionally, for image re-encoding, add the standard library `javax.imageio.ImageIO` which is included with the JDK.

**Vulnerable Code**

```java
@PostMapping("/api/images")
public ResponseEntity<String> uploadImage(@RequestParam("file") MultipartFile file) throws IOException {
    String contentType = file.getContentType();
    // VULNERABLE: Validates only client-supplied Content-Type header, not actual file bytes
    if (contentType == null || !ALLOWED_CONTENT_TYPES.contains(contentType)) {
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Unsupported image type");
    }

    String extension = EXTENSION_BY_CONTENT_TYPE.get(contentType);
    String storedName = UUID.randomUUID() + extension;
    Path destination = UPLOAD_DIR.resolve(storedName);

    // SINK: File written to disk without verifying actual content
    Files.copy(file.getInputStream(), destination, StandardCopyOption.REPLACE_EXISTING);

    return ResponseEntity.ok(storedName);
}
```

**Fixed Code**

```java
import org.apache.tika.Tika;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

@RestController
public class ImageUploadController {

    private static final Set<String> ALLOWED_CONTENT_TYPES = Set.of("image/png", "image/jpeg");

    private static final Map<String, String> EXTENSION_BY_CONTENT_TYPE = Map.of(
            "image/png", ".png",
            "image/jpeg", ".jpg"
    );

    private static final Path UPLOAD_DIR = Paths.get("/var/data/uploads/images");
    private static final long MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB limit
    private static final Tika tika = new Tika();

    @PostMapping("/api/images")
    public ResponseEntity<String> uploadImage(@RequestParam("file") MultipartFile file) throws IOException {
        // Validate file size
        if (file.getSize() > MAX_FILE_SIZE) {
            return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE).body("File too large");
        }

        // Read file bytes for content inspection
        byte[] fileBytes = file.getBytes();

        // Detect actual file type from bytes using Tika, not client-supplied Content-Type
        String detectedType = tika.detect(fileBytes);

        // Validate detected type against allowlist
        if (!ALLOWED_CONTENT_TYPES.contains(detectedType)) {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Unsupported image type");
        }

        // Get extension from the detected type (canonical, server-controlled)
        String extension = EXTENSION_BY_CONTENT_TYPE.get(detectedType);
        if (extension == null || extension.isEmpty()) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Unable to determine file extension");
        }

        // Re-encode image to strip embedded scripts, malformed metadata, or polyglot payloads
        byte[] reEncodedBytes;
        try {
            BufferedImage image = ImageIO.read(new ByteArrayInputStream(fileBytes));
            if (image == null) {
                return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Invalid image data");
            }

            ByteArrayOutputStream reEncodedOutput = new ByteArrayOutputStream();
            String format = detectedType.equals("image/png") ? "png" : "jpg";
            ImageIO.write(image, format, reEncodedOutput);
            reEncodedBytes = reEncodedOutput.toByteArray();
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Failed to process image");
        }

        // Generate random filename with safe extension
        String storedName = UUID.randomUUID() + extension;
        Path destination = UPLOAD_DIR.resolve(storedName);

        // Write re-encoded bytes to disk using CREATE_NEW to prevent overwrites
        Files.write(destination, reEncodedBytes, StandardOpenOption.CREATE_NEW);

        return ResponseEntity.ok(storedName);
    }
}
```

## Explanation

The original code trusted the client-supplied `Content-Type` header (`file.getContentType()`) to validate the uploaded file type. This is a critical vulnerability because the Content-Type header is trivially forgeable—an attacker can upload a JSP shell, executable, or other dangerous file with a forged `Content-Type: image/jpeg` header and bypass the allowlist check.

The fix implements three key defences:

1. **Content inspection with Tika**: Uses Apache Tika's `tika.detect(bytes)` to inspect the actual file bytes and determine the real type, immune to client-supplied headers. The detected type is then validated against the allowlist.

2. **Image re-encoding**: For image uploads, the code reads the validated bytes with `ImageIO.read()` and re-writes them with `ImageIO.write()`. This decode-and-re-encode process strips embedded scripts, malformed metadata, polyglot payloads, and any active content that might exist after the valid image header—a simple signature check alone is not sufficient because a valid PNG with appended executable content still detects as `image/png`.

3. **Safe downstream handling**: The extension is derived from the Tika-detected type through the canonical `EXTENSION_BY_CONTENT_TYPE` map, not from the client-supplied header or filename. All downstream file handling uses the detected type and safe filename, not the original request values. The file size is also validated, and `StandardOpenOption.CREATE_NEW` is used instead of `REPLACE_EXISTING` to prevent overwriting existing files.

## Behaviour changes

1. **File size validation added**: The fix enforces a 5 MB limit via `MAX_FILE_SIZE`. This is a security-relevant change that prevents denial-of-service via large file uploads. Adjust the limit to match your application's requirements.

2. **File I/O strategy changed**: Original uses `Files.copy()` with `StandardCopyOption.REPLACE_EXISTING` and returns the byte count. Fixed code uses `Files.write()` with `StandardOpenOption.CREATE_NEW`, which prevents accidental overwrites and throws if the file already exists. The return value is not used in the original code, so this is safe. If callers depend on the byte count, capture `reEncodedBytes.length` instead.

3. **Error handling expanded**: The fixed code introduces additional validation points (size check, Tika detection failure, image parse failure). Each returns an appropriate HTTP status code. The original code only checked the allowlist. Applications expecting a simpler failure contract should adjust the error responses as needed.

4. **Memory footprint increased**: The fixed code reads the entire file into memory (byte array) for content inspection and image re-encoding. For very large files, this may exceed available heap. Configure `spring.servlet.multipart.max-file-size` in `application.properties` to enforce a reasonable limit server-wide, and adjust the `MAX_FILE_SIZE` constant to match.

5. **Tika detection call**: Tika's first call triggers lazy initialization of its MIME-type database, which may add 100-300 ms to the first request. Subsequent calls are fast. If latency is critical, consider initializing Tika eagerly at startup.

