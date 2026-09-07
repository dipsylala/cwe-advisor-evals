## Verdict
exploitable

## Source
Untrusted file content from `MultipartFile file` parameter in HTTP request

## Fix

**Vulnerable code:**
```java
@PostMapping("/api/images")
public ResponseEntity<String> uploadImage(@RequestParam("file") MultipartFile file) throws IOException {
    String contentType = file.getContentType();
    if (contentType == null || !ALLOWED_CONTENT_TYPES.contains(contentType)) {
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Unsupported image type");
    }

    String extension = EXTENSION_BY_CONTENT_TYPE.get(contentType);
    String storedName = UUID.randomUUID() + extension;
    Path destination = UPLOAD_DIR.resolve(storedName);

    // VULNERABILITY: Only validates client-supplied Content-Type header, not actual file bytes
    Files.copy(file.getInputStream(), destination, StandardCopyOption.REPLACE_EXISTING);

    return ResponseEntity.ok(storedName);
}
```

**Fixed code:**
```java
@PostMapping("/api/images")
public ResponseEntity<String> uploadImage(@RequestParam("file") MultipartFile file) throws IOException {
    byte[] fileBytes = file.getBytes();

    // Detect actual content type from file bytes using Tika, not client-supplied header
    Tika tika = new Tika();
    String detectedType = tika.detect(fileBytes);

    // Validate detected type against allowlist
    if (detectedType == null || !ALLOWED_CONTENT_TYPES.contains(detectedType)) {
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Unsupported image type");
    }

    // Re-encode images to strip embedded scripts or malformed metadata
    if (detectedType.startsWith("image/")) {
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(fileBytes);
            BufferedImage img = ImageIO.read(bais);
            if (img == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid image format");
            }
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            String formatName = detectedType.equals("image/png") ? "png" : "jpg";
            ImageIO.write(img, formatName, baos);
            fileBytes = baos.toByteArray();
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Failed to process image");
        }
    }

    // Use detected type to determine extension, not client-supplied value
    String extension = EXTENSION_BY_CONTENT_TYPE.get(detectedType);
    String storedName = UUID.randomUUID() + extension;
    Path destination = UPLOAD_DIR.resolve(storedName);

    // Write with CREATE_NEW to prevent overwrites and use validated bytes
    Files.write(destination, fileBytes, StandardOpenOption.CREATE_NEW);

    return ResponseEntity.ok(storedName);
}
```

**Required imports to add:**
```java
import org.apache.tika.Tika;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.file.StandardOpenOption;
```

## Explanation
The vulnerability occurs because the code validates only the client-supplied `Content-Type` HTTP header without inspecting the actual file bytes. An attacker can upload a malicious executable, web shell, or script disguised as an image by providing a forged `Content-Type` header. The fix detects the real file type using Apache Tika's magic-byte inspection via `tika.detect(bytes)` on the actual file content, validates that detected type against the allowlist, and uses only the validated detected type for extension lookup. For images, the fix re-encodes the file using `ImageIO.read()` and `ImageIO.write()`, which discards any appended payloads or embedded scripts after the image data. The file is written with `StandardOpenOption.CREATE_NEW` using the re-encoded clean bytes, ensuring only legitimate image content is persisted.

## Behaviour changes
- **Dependency added:** Apache Tika (`org.apache.tika:tika-core`) for content-type detection from file bytes.
- **Bytes loaded into memory:** `file.getBytes()` replaces streaming via `file.getInputStream()`, loading the entire upload into a byte array before validation. This enables Tika detection and image re-encoding but requires adequate heap space for the maximum file size.
- **Image re-encoding:** Images are decoded and re-encoded via `ImageIO`, which strips embedded scripts, polyglot payloads, and malformed metadata but adds CPU overhead and may lose EXIF or other non-pixel data.
- **Write mode changed:** `Files.copy()` with `REPLACE_EXISTING` becomes `Files.write()` with `CREATE_NEW`. This fails if a file with the generated name already exists (a safety guarantee for random UUIDs in single-threaded scenarios, but multiprocess concurrent uploads to the same directory could contend). `REPLACE_EXISTING` permitted overwriting; `CREATE_NEW` does not.
- **Error handling added:** Image processing failures (invalid format, re-encode failure) now return HTTP 400 instead of propagating exceptions.
- **Content validation strengthened:** Only allowlisted MIME types detected from actual file bytes are accepted; client-supplied `Content-Type` header is ignored.
