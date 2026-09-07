## Verdict

Exploitable. The code validates only the client-supplied Content-Type header, not the actual file bytes. An attacker can upload malicious executables (e.g., `.exe`, PHP shell) and forge the header to "image/png" or "image/jpeg" to bypass the allowlist, resulting in a dangerous file being written to disk and potentially executed.

## Source

`file.getContentType()` — the HTTP Content-Type header supplied by the client in line 33, used for validation in line 34. This header is client-controlled and not verified against actual file content.

## Fix

**Vulnerable code (lines 32-47):**
```java
@PostMapping("/api/images")
public ResponseEntity<String> uploadImage(@RequestParam("file") MultipartFile file) throws IOException {
    String contentType = file.getContentType();
    if (contentType == null || !ALLOWED_CONTENT_TYPES.contains(contentType)) {
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Unsupported image type");
    }

    // Filename generation is already safe: a random UUID with the extension
    // looked up from a fixed map keyed by the declared content type.
    String extension = EXTENSION_BY_CONTENT_TYPE.get(contentType);
    String storedName = UUID.randomUUID() + extension;
    Path destination = UPLOAD_DIR.resolve(storedName);

    // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    Files.copy(file.getInputStream(), destination, StandardCopyOption.REPLACE_EXISTING);

    return ResponseEntity.ok(storedName);
}
```

**Fixed code:**
```java
@PostMapping("/api/images")
public ResponseEntity<String> uploadImage(@RequestParam("file") MultipartFile file) throws IOException {
    // Read file bytes for content inspection and re-encoding
    byte[] fileBytes = file.getBytes();
    
    // Detect actual content type from file bytes (magic bytes), not client-supplied header
    Tika tika = new Tika();
    String detectedContentType = tika.detect(fileBytes);
    
    // Validate detected type (not client-supplied header) against allowlist
    if (!ALLOWED_CONTENT_TYPES.contains(detectedContentType)) {
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Unsupported image type");
    }

    // Get extension from detected type via allowlist map (not from client-supplied filename or header)
    String extension = EXTENSION_BY_CONTENT_TYPE.get(detectedContentType);
    String storedName = UUID.randomUUID() + extension;
    Path destination = UPLOAD_DIR.resolve(storedName);

    // Re-encode image to strip embedded scripts and malformed metadata
    BufferedImage image = ImageIO.read(new ByteArrayInputStream(fileBytes));
    if (image == null) {
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Could not read image data");
    }
    
    // Write re-encoded image; this discards any content after the valid image structure
    String formatName = detectedContentType.equals("image/png") ? "PNG" : "JPEG";
    try (OutputStream out = Files.newOutputStream(destination, StandardOpenOption.CREATE_NEW)) {
        if (!ImageIO.write(image, formatName, out)) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to encode image");
        }
    }

    return ResponseEntity.ok(storedName);
}
```

**Required imports:**
```java
import org.apache.tika.Tika;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.nio.file.StandardOpenOption;
```

**Maven dependency to add:**
```xml
<dependency>
    <groupId>org.apache.tika</groupId>
    <artifactId>tika-core</artifactId>
    <!-- Version must be verified against SCA/security advisory data -->
</dependency>
```

## Explanation

The original code trusts the client-supplied Content-Type header to validate file type, which can be forged. The fix uses Apache Tika to detect the actual file content by inspecting magic bytes (file signature), which cannot be spoofed without altering the actual file structure. After validating the detected type against the allowlist, the code re-encodes the image using `ImageIO.read()` then `ImageIO.write()`, which reconstructs the image from decoded pixel data only and discards any embedded content, scripts, or metadata that may have been appended after the valid image structure. The stored filename and extension are now derived from the Tika-detected type (through the allowlist map), not from the client-supplied header or original filename, breaking the taint chain and ensuring only the intended file type reaches storage.

## Behaviour changes

1. **File bytes are now read into memory** (`file.getBytes()`) to enable content detection. This adds memory overhead proportional to file size; for multi-gigabyte uploads, callers may need to increase heap size or stream the bytes instead.

2. **ImageIO re-encoding** reconstructs the image from pixel data, discarding the original file structure. This:
   - Strips embedded EXIF/metadata, which may break client expectations if the upload endpoint is intended to preserve metadata
   - Changes file size and binary content (lossy for JPEG due to re-compression; lossless for PNG)
   - Adds CPU overhead (decode + re-encode cycle)

3. **File creation mode changed** from `StandardCopyOption.REPLACE_EXISTING` (overwrites any file at destination) to `StandardOpenOption.CREATE_NEW` (throws `FileAlreadyExistsException` if the path exists). Since filenames are random UUIDs, collisions are virtually impossible, but the exception is now semantically stricter and prevents silent overwrites of concurrent uploads to the same generated path.

4. **Error paths expanded**: New error responses for "Could not read image data" (corrupted image) and "Failed to encode image" (ImageIO write failure). The original code would have silently failed with an IOException thrown to the caller.

5. **New dependency** on Apache Tika (`tika-core`) added to the classpath.
