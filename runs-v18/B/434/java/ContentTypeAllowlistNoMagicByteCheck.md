## Verdict
exploitable

## Source
`MultipartFile.getInputStream()` and `file.getContentType()` at line 33, where `getContentType()` is client-supplied HTTP request header

## Fix
The vulnerability stems from validating only the client-supplied Content-Type header without inspecting the actual file bytes. An attacker can forge the header to claim a PNG or JPEG while uploading a malicious executable or shell script. The fix detects the actual file type from its bytes using Apache Tika, re-encodes images through ImageIO to strip embedded payloads, and uses only the detected type for validation and storage decisions.

### File: ImageUploadController.java
```java
package com.example.upload;

import org.apache.tika.Tika;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@RestController
public class ImageUploadController {

    private static final Set<String> ALLOWED_CONTENT_TYPES = Set.of("image/png", "image/jpeg");

    private static final Map<String, String> EXTENSION_BY_CONTENT_TYPE = Map.of(
            "image/png", ".png",
            "image/jpeg", ".jpg"
    );

    private static final Path UPLOAD_DIR = Paths.get("/var/data/uploads/images");
    private static final Tika tika = new Tika();

    @PostMapping("/api/images")
    public ResponseEntity<String> uploadImage(@RequestParam("file") MultipartFile file) throws IOException {
        // Read file bytes for content detection
        byte[] fileBytes = file.getBytes();

        // Detect actual content type from file bytes, not from client-supplied header
        String detectedContentType = tika.detect(fileBytes);

        // Validate against allowlist using the detected type
        if (!ALLOWED_CONTENT_TYPES.contains(detectedContentType)) {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Unsupported image type");
        }

        // Use the detected content type to determine extension, not the client-supplied one
        String extension = EXTENSION_BY_CONTENT_TYPE.get(detectedContentType);
        String storedName = UUID.randomUUID() + extension;
        Path destination = UPLOAD_DIR.resolve(storedName);

        // Re-encode the image to strip any embedded scripts or malformed metadata
        byte[] encodedImageBytes = reencodeImage(fileBytes, detectedContentType);

        // Write re-encoded image to destination
        Files.write(destination, encodedImageBytes, StandardOpenOption.CREATE_NEW);

        return ResponseEntity.ok(storedName);
    }

    /**
     * Re-encodes an image from bytes, stripping embedded scripts and metadata.
     * This removes any payload appended after the image data.
     */
    private byte[] reencodeImage(byte[] imageBytes, String contentType) throws IOException {
        ByteArrayInputStream input = new ByteArrayInputStream(imageBytes);
        BufferedImage image = ImageIO.read(input);

        if (image == null) {
            throw new IOException("Failed to decode image");
        }

        // Determine format string for ImageIO.write()
        String format = contentType.equals("image/png") ? "png" : "jpg";

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        boolean written = ImageIO.write(image, format, output);
        if (!written) {
            throw new IOException("Failed to encode image");
        }

        return output.toByteArray();
    }
}
```

## Explanation
The fix replaces trust in the client-supplied Content-Type header with inspection of actual file bytes. First, it reads all bytes from the uploaded file and passes them to Apache Tika's `tika.detect()`, which examines the file's magic bytes (signature) to determine its real type. The detected type is then validated against the allowlist; if it does not match, the upload is rejected. The extension for storage is derived from the detected type using the allowlist map, ensuring the stored filename cannot be controlled by the attacker. Critically, for image uploads, the file is re-encoded through `ImageIO.read()` and `ImageIO.write()`, which decodes the image pixels and re-emits them in the specified format. This strips any embedded malicious content, appended payloads (e.g., a PNG with a script after the IEND marker), or malformed metadata that could later be exploited. The re-encoded bytes are written to disk using `StandardOpenOption.CREATE_NEW`, which fails atomically if the generated name already exists, preventing accidental overwrites. This multi-layered approach—content detection, re-encoding, and generated filenames—eliminates the path from forged headers to arbitrary file upload.

## Behaviour changes
- `file.getInputStream()` is replaced with `file.getBytes()` to enable content inspection; `getBytes()` loads the entire file into memory, suitable for typical image uploads but not for very large files
- `Files.copy()` is replaced with `Files.write()` using `StandardOpenOption.CREATE_NEW`, which fails if the destination already exists (stricter than the original `REPLACE_EXISTING`, improving atomicity but changing error semantics)
- A new private method `reencodeImage()` is added to decode and re-emit images, discarding any payload appended after valid image data
- An additional import of Apache Tika is required: `org.apache.tika:tika-core` as a Maven dependency (or equivalent in other build systems); no version is specified here, as the loaded guidance does not provide one—the minimum safe version must be confirmed against SCA/dependency-check tooling before deployment
- The method now throws `IOException` from image re-encoding in addition to the original file operations, which is already declared in the original signature
- Response remains the same: a 415 (Unsupported Media Type) for disallowed types, or 200 OK with the generated storage filename on success

## Verification
Java syntax verified by inspection of import statements, method signatures, and API usage against standard JDK and Spring Framework APIs:
- `java.nio.file.Files`, `StandardOpenOption.CREATE_NEW` - standard Java NIO (JDK 7+)
- `javax.imageio.ImageIO` - standard Java image I/O (JDK 5+)
- `java.awt.image.BufferedImage` - standard Java AWT (JDK 1.2+)
- `org.apache.tika.Tika` - Apache Tika Core library (must be added as a dependency; method `detect(byte[])` is the public API)
- Spring Framework annotations and classes - already present in the original code

All method calls match their declared signatures:
- `ImageIO.read(InputStream)` returns `BufferedImage` or `null`; null check is performed before use
- `ImageIO.write(RenderedImage, String, OutputStream)` returns `boolean`; result is checked before returning re-encoded bytes
- `tika.detect(byte[])` returns `String` MIME type; result is used directly in allowlist check and map lookup
- `Files.write(Path, byte[], OpenOption...)` is called with valid arguments; will throw `FileAlreadyExistsException` if destination exists (distinct from `REPLACE_EXISTING` semantics)

No additional syntax errors detected. The fix is ready to compile against Spring Boot with Tika on the classpath.

## Assumptions
- **Language inference:** Java inferred from `.java` file extension.
- **CWE routing:** No child CWE redirect required; CWE-434 is the correct classification.
- **Tika version:** The guidance names `org.apache.tika:tika-core` but provides no minimum version. Assume the latest stable release; a scanner or SCA tool must confirm no known CVEs in the resolved version before deployment.
- **ImageIO codec availability:** The fix assumes JPEG and PNG codecs are available in the JDK's ImageIO (true for all standard JDK distributions).
- **File size:** `file.getBytes()` loads the entire file into memory. For this image upload endpoint, typical images are megabytes and fit in application memory; for production, confirm heap size is adequate for the configured `spring.servlet.multipart.max-file-size`.
- **Content-Type edge case:** When Tika detects `image/jpg` (non-standard) instead of `image/jpeg`, the allowlist lookup will fail and the upload will be rejected. If this is undesired, the allowlist or map may need to include both variants; however, per the guidance, validation should be strict and rejecting non-canonical types is correct behaviour.
