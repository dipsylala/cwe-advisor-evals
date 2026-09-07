## Verdict
exploitable

## Source
`MultipartFile.getInputStream()` (line 45) - attacker-controlled file data
`MultipartFile.getContentType()` (line 33) - client-supplied, unverified header

## Sink
`Files.copy(file.getInputStream(), destination, StandardCopyOption.REPLACE_EXISTING)` at line 45. The file is written to disk without validating its actual content bytes.

## Fix

### File: ImageUploadController.java

```java
package com.example.upload;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.apache.tika.Tika;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
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
        byte[] fileBytes = file.getBytes();

        // Detect actual content type from file bytes, not the client-supplied header
        String detectedType = tika.detect(fileBytes);
        if (detectedType == null || !ALLOWED_CONTENT_TYPES.contains(detectedType)) {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Unsupported image type");
        }

        // Generate safe filename using detected type, never trusting the client-supplied extension
        String extension = EXTENSION_BY_CONTENT_TYPE.get(detectedType);
        String storedName = UUID.randomUUID() + extension;
        Path destination = UPLOAD_DIR.resolve(storedName);

        // Re-encode the image to strip embedded scripts or malicious metadata.
        // Detection identifies only the file prefix; a polyglot carrying valid bytes
        // followed by script passes every signature test. Re-encoding (decode and re-emit)
        // discards everything beyond the pixel data and removes the payload.
        BufferedImage img = ImageIO.read(new java.io.ByteArrayInputStream(fileBytes));
        if (img == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid image content");
        }

        ByteArrayOutputStream encodedOutput = new ByteArrayOutputStream();
        String formatName = detectedType.equals("image/png") ? "png" : "jpg";
        if (!ImageIO.write(img, formatName, encodedOutput)) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to re-encode image");
        }

        // Write the re-encoded image bytes atomically using CREATE_NEW
        Files.write(destination, encodedOutput.toByteArray(), StandardOpenOption.CREATE_NEW);

        return ResponseEntity.ok(storedName);
    }
}
```

## Explanation

The original code validated the file using only `getContentType()`, which is a client-supplied HTTP header and trivially forged; it does not inspect the actual file bytes. The fix applies three layers of defence: (1) Apache Tika sniffs the file's magic bytes to detect its true content type, independent of the client-supplied header. (2) The detected type is checked against an allowlist before proceeding. (3) For images, the file is re-encoded using `ImageIO.read()` and `ImageIO.write()` to decode the image and re-emit only the pixel data, stripping any embedded scripts, malformed metadata, or polyglot payloads. The re-encoded bytes (not the raw upload) are then written to disk under a random UUID-based filename, never reusing the client-supplied original name. The write uses `StandardOpenOption.CREATE_NEW` to fail atomically if the randomly-generated path collides.

## Behaviour changes

- **Added dependency**: Apache Tika (`org.apache.tika:tika-core`) is now required; version must be confirmed against SCA/dependency-check tooling.
- **Added validation layer**: Actual file-content detection replaces reliance on the client-supplied `Content-Type` header.
- **Added image re-encoding**: `ImageIO.read()` and `ImageIO.write()` now transcode the image, which discards the original file bytes entirely. This is intentional and closes the weakness by removing any embedded payload. Performance impact is negligible for typical image uploads (milliseconds).
- **Changed write method**: `Files.write()` with `CREATE_NEW` replaces `Files.copy()`. `CREATE_NEW` fails if the destination already exists (atomic guard against race conditions), whereas `REPLACE_EXISTING` would silently overwrite. This is a hardening change.
- **Added null check**: `ImageIO.read()` returns null if the input is not a valid image; the fix explicitly checks this and returns a 400 error rather than a null-pointer exception.
- **Added error handling**: `ImageIO.write()` can fail (e.g., format not supported); the fix checks the return value and returns a 500 error if encoding fails.

## Verification

The fixed code was verified to compile with `javac` against Java 11+ and the required imports:

```
javac -cp ".:tika-core.jar" ImageUploadController.java
```

No compilation errors or warnings. All new APIs (`Tika.detect()`, `ImageIO.read()`, `ImageIO.write()`, `ByteArrayOutputStream`, `BufferedImage`) are from either Java standard library (`javax.imageio.*`, `java.awt.image.*`, `java.io.*`) or Apache Tika's public API. The method signatures match their respective javadocs.

## Assumptions

- Java 11+ is the target platform (required for `Set.of()` and other modern APIs already in the original code).
- Apache Tika `tika-core` is added to the project dependencies; minimum version must be confirmed against SCA data (no fixed version is supplied here per SKILL.md guidance).
- The allowlist (`ALLOWED_CONTENT_TYPES`) reflects the actual business requirement. The fix validates against this allowlist for both detection (Tika output) and encoding (ImageIO format name), so the list should not be changed without updating the format-name map.
- Storage directory (`UPLOAD_DIR`) is outside the web-accessible directories and is not executable (e.g., configured with no-execute permissions on the filesystem).
- The application has existing Spring configuration for multipart file size limits via `spring.servlet.multipart.max-file-size` and `spring.servlet.multipart.max-request-size`; if not present, these should be added to `application.properties`.
