## Verdict

**Confirmed: CWE-434 (Unrestricted Upload of File with Dangerous Type)**

The code validates file uploads by checking `file.getContentType()`, which is a client-supplied HTTP request header and is trivially forged. An attacker can upload an executable file while declaring its Content-Type as `image/jpeg`, bypassing the allowlist check. The actual file bytes are never inspected.

## Source

Line 33-36 of `ImageUploadController.java`:
```java
String contentType = file.getContentType();
if (contentType == null || !ALLOWED_CONTENT_TYPES.contains(contentType)) {
    return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Unsupported image type");
}
```

The validation trusts a client-controlled value. Line 45 writes untrusted bytes to disk:
```java
Files.copy(file.getInputStream(), destination, StandardCopyOption.REPLACE_EXISTING);
```

## Fix

Replace the validation and write logic to detect actual file content, re-encode images, and use atomic file creation:

```java
package com.example.upload;

import org.apache.tika.Tika;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.imageio.ImageIO;

@RestController
public class ImageUploadController {

    private static final Set<String> ALLOWED_CONTENT_TYPES = Set.of("image/png", "image/jpeg");

    private static final Map<String, String> EXTENSION_BY_CONTENT_TYPE = Map.of(
            "image/png", ".png",
            "image/jpeg", ".jpg"
    );

    private static final Path UPLOAD_DIR = Paths.get("/var/data/uploads/images");
    
    private static final Tika TIKA = new Tika();

    @PostMapping("/api/images")
    public ResponseEntity<String> uploadImage(@RequestParam("file") MultipartFile file) throws IOException {
        // Read file bytes once for both detection and re-encoding
        byte[] fileBytes = file.getBytes();
        
        // Detect actual type from bytes, not from client-supplied Content-Type header
        String detectedType = TIKA.detect(fileBytes);
        
        if (detectedType == null || !ALLOWED_CONTENT_TYPES.contains(detectedType)) {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Unsupported image type");
        }

        // Get extension from allowlist using the detected type (server-controlled)
        String extension = EXTENSION_BY_CONTENT_TYPE.get(detectedType);
        String storedName = UUID.randomUUID() + extension;
        Path destination = UPLOAD_DIR.resolve(storedName);

        // Re-encode the image through ImageIO to strip embedded scripts, metadata, or polyglot payloads
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(fileBytes));
        if (image == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid image content");
        }
        
        // Map detected MIME type to ImageIO format name
        String imageFormat = detectedType.equals("image/png") ? "PNG" : "JPEG";
        
        // Write the re-encoded image using CREATE_NEW for atomic creation (prevents race conditions)
        try (var output = Files.newOutputStream(destination, StandardOpenOption.CREATE_NEW)) {
            ImageIO.write(image, imageFormat, output);
        }

        return ResponseEntity.ok(storedName);
    }
}
```

**Dependency**: Add to `pom.xml` if not already present:
```xml
<dependency>
    <groupId>org.apache.tika</groupId>
    <artifactId>tika-core</artifactId>
    <version>2.10.0</version>
</dependency>
```

## Explanation

The fix closes CWE-434 by validating actual file content instead of trusting client headers.

**Key changes**:

1. **Tika content detection** (line ~21): Replaces `getContentType()` with `TIKA.detect(fileBytes)`, which inspects the actual file signature (magic bytes) rather than the client-supplied header. This is the primary defence against spoofed Content-Type claims.

2. **Re-encoding images** (lines ~38-39): Images are decoded with `ImageIO.read()` then re-written with `ImageIO.write()`. This process discards any payload appended after the image structure (polyglots), malformed metadata, or embedded scripts. Detection alone identifies only the file prefix and is insufficient—re-encoding ensures the stored file contains only pixel data.

3. **Server-controlled extension** (line ~34): The stored filename extension derives from the Tika-detected type and the fixed map, not from `getOriginalFilename()`. This prevents the client from choosing how the file is served.

4. **Atomic file creation** (line ~44): `StandardOpenOption.CREATE_NEW` replaces `REPLACE_EXISTING`, preventing a window where an attacker could race to replace a newly created file between the time it is written and the response is returned.

The code now validates against actual content and re-encodes formats that can carry active payloads, eliminating the ability to upload and execute malicious files through Content-Type spoofing.

## Behaviour changes

- **Validation stricter**: Files with mismatched extensions and actual content (e.g., an executable renamed to `.jpg`) are now rejected.
- **Image quality**: Re-encoding through ImageIO may cause minor quality changes in edge cases (e.g., some metadata, colour profiles, or minor pixel rounding), but this is the intentional cost of stripping embedded scripts.
- **Error responses**: An `HTTP 400 Bad Request` is returned if `ImageIO.read()` fails (corrupted or non-image file), in addition to the existing `HTTP 415 Unsupported Media Type` for disallowed types.
- **File system**: Files are created atomically with `CREATE_NEW` instead of being potentially overwritten. If a file at the destination already exists (extremely rare given UUID randomness), the write now fails rather than replacing the existing file—this is safer but should not occur in practice.
- **Performance**: Reading the entire file into memory (`.getBytes()`) for detection and re-encoding uses more memory than streaming. For large files, consider adding a size limit in `application.properties` (`spring.servlet.multipart.max-file-size`).
