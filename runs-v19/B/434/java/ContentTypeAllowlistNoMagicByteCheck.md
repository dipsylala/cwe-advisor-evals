## Verdict

The code validates the client-supplied `Content-Type` header against an allowlist but does not inspect the actual file bytes. An attacker can upload a malicious executable with a forged `image/jpeg` header, passing validation and being written to disk with an image extension, where it may be executed or served back to clients as active content.

## Source

**File:** ImageUploadController.java  
**Line:** 45  
**Call chain:** `@PostMapping` handler receives `MultipartFile`, validates only `getContentType()` (client-controlled), then writes raw bytes with `Files.copy()`.

## Fix

Replace the unsafe content-type validation with actual content detection. The fixed code:
1. Reads the file bytes into memory
2. Uses Apache Tika to detect the real content type from the file signature
3. Validates the detected type against the allowlist (not the client-supplied header)
4. For images, re-encodes with `ImageIO` to strip embedded payloads
5. Stores with the Tika-detected extension, not client-supplied values

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
import javax.imageio.ImageWriter;
import javax.imageio.stream.ImageOutputStream;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Iterator;
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

    private static final long MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB

    @PostMapping("/api/images")
    public ResponseEntity<String> uploadImage(@RequestParam("file") MultipartFile file) throws IOException {
        // Enforce size limit before reading bytes
        if (file.getSize() > MAX_FILE_SIZE) {
            return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                    .body("File exceeds maximum size");
        }

        // Read file bytes
        byte[] fileBytes = file.getBytes();
        if (fileBytes.length == 0) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("File is empty");
        }

        // Detect actual content type from file signature (magic bytes)
        String detectedContentType = tika.detect(fileBytes);

        // Validate detected type against allowlist (not client-supplied header)
        if (!ALLOWED_CONTENT_TYPES.contains(detectedContentType)) {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                    .body("File content does not match an allowed image type");
        }

        String extension = EXTENSION_BY_CONTENT_TYPE.get(detectedContentType);
        String storedName = UUID.randomUUID() + extension;
        Path destination = UPLOAD_DIR.resolve(storedName);

        // Re-encode image to strip embedded payloads or malformed metadata
        byte[] sanitizedBytes = reencodeImage(fileBytes, detectedContentType);

        // Write with CREATE_NEW to fail if file somehow already exists
        Files.write(destination, sanitizedBytes, StandardOpenOption.CREATE_NEW);

        return ResponseEntity.ok(storedName);
    }

    /**
     * Re-encodes the image by decoding and re-saving it, which removes embedded
     * scripts, malformed metadata, or polyglot payloads that raw byte inspection
     * alone would not catch.
     */
    private byte[] reencodeImage(byte[] imageBytes, String contentType) throws IOException {
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(imageBytes));
        if (image == null) {
            throw new IOException("Failed to decode image: ImageIO returned null");
        }

        // Determine the output format from the detected content type
        String formatName = contentType.equals("image/png") ? "png" : "jpg";

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        if (!ImageIO.write(image, formatName, output)) {
            throw new IOException("Failed to write image: no writer found for format " + formatName);
        }
        return output.toByteArray();
    }
}
```

## Explanation

The vulnerability lies in line 34 of the original code: `ALLOWED_CONTENT_TYPES.contains(contentType)` where `contentType` comes from the client-supplied HTTP `Content-Type` header. An attacker can set this header to `image/jpeg` while uploading an executable file, bypassing the allowlist entirely.

**Key changes:**

1. **Tika content detection** (line 79-80): `tika.detect(fileBytes)` inspects the actual file signature, not the HTTP header. This detects the real file type regardless of what the client claims.

2. **Validate detected type** (line 82-86): The allowlist check now uses the server-detected type, not the client-supplied one. Only files whose bytes match an allowed image signature pass.

3. **Image re-encoding** (line 94): `reencodeImage()` decodes the image with `ImageIO.read()` and re-encodes it. This strips embedded scripts, polyglot payloads, or malformed metadata that static content inspection cannot remove. A valid PNG with an appended executable payload will decode as just the PNG pixels and be re-encoded without the payload.

4. **CREATE_NEW** (line 94): Replaces `REPLACE_EXISTING` to fail if the destination (extremely unlikely with UUIDs) already exists, adding a defensive layer.

5. **Size limit** (line 50-53): Prevents memory exhaustion from huge files before they're fully read.

6. **Null checks** (line 104): ImageIO methods can return null; the code now handles this safely.

The fix enforces the CWE-434 principle: validate against actual content, not client claims, and re-encode formats that can carry active content before trusting them.

## Behaviour changes

- Uploads with mismatched extension and content (e.g., executable disguised as `.jpg`) are now rejected.
- All images are re-encoded, which may change compression ratios, metadata stripping, or color space handling. Downstream processes consuming these files will see re-encoded images, not raw uploads.
- Oversized files (>5 MB) are rejected before processing. The size limit is configurable via `MAX_FILE_SIZE`.
- Requests that upload corrupted or undecodable images now fail with an error instead of silently storing the corrupted bytes.

**Added dependency:** Apache Tika (`org.apache.tika:tika-core`). Add to `pom.xml` or `build.gradle`:
- Maven: `<dependency><groupId>org.apache.tika</groupId><artifactId>tika-core</artifactId><version>2.9.0</version></dependency>`
- Gradle: `implementation 'org.apache.tika:tika-core:2.9.0'`
