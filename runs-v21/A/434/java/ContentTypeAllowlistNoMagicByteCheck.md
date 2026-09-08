## Verdict
The vulnerability is real. The code validates only the declared Content-Type header but does not verify the actual file content. An attacker can upload a malicious executable (e.g., JSP, EXE) with a spoofed `image/png` or `image/jpeg` Content-Type header, bypassing the allowlist check.

## Source
Line 45: `Files.copy(file.getInputStream(), destination, StandardCopyOption.REPLACE_EXISTING);`

The file is saved without validating the actual magic bytes, allowing content-type spoofing attacks.

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

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
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

    // PNG magic bytes: 89 50 4E 47
    private static final byte[] PNG_MAGIC = {(byte) 0x89, 0x50, 0x4E, 0x47};
    // JPEG magic bytes: FF D8 FF
    private static final byte[] JPEG_MAGIC = {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF};

    @PostMapping("/api/images")
    public ResponseEntity<String> uploadImage(@RequestParam("file") MultipartFile file) throws IOException {
        String contentType = file.getContentType();
        if (contentType == null || !ALLOWED_CONTENT_TYPES.contains(contentType)) {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Unsupported image type");
        }

        // Verify the actual file content matches the declared type via magic bytes
        if (!isValidImageMagicBytes(file.getInputStream(), contentType)) {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("File content does not match declared image type");
        }

        // Filename generation is already safe: a random UUID with the extension
        // looked up from a fixed map keyed by the declared content type.
        String extension = EXTENSION_BY_CONTENT_TYPE.get(contentType);
        String storedName = UUID.randomUUID() + extension;
        Path destination = UPLOAD_DIR.resolve(storedName);

        Files.copy(file.getInputStream(), destination, StandardCopyOption.REPLACE_EXISTING);

        return ResponseEntity.ok(storedName);
    }

    private boolean isValidImageMagicBytes(InputStream inputStream, String contentType) throws IOException {
        byte[] header = new byte[4];
        int bytesRead = inputStream.read(header);
        if (bytesRead < 3) {
            return false;
        }

        if ("image/png".equals(contentType)) {
            return bytesRead >= 4 && matches(header, PNG_MAGIC);
        } else if ("image/jpeg".equals(contentType)) {
            return matches(header, JPEG_MAGIC);
        }

        return false;
    }

    private boolean matches(byte[] header, byte[] magic) {
        for (int i = 0; i < magic.length; i++) {
            if (header[i] != magic[i]) {
                return false;
            }
        }
        return true;
    }
}
```

## Explanation
The fix adds magic-byte validation to ensure the uploaded file's actual content matches the declared Content-Type:

1. **PNG validation**: Checks for the PNG magic bytes `89 50 4E 47` at the start of the file.
2. **JPEG validation**: Checks for the JPEG magic bytes `FF D8 FF` at the start of the file.
3. **isValidImageMagicBytes()**: Reads the first 4 bytes of the file and compares them against the expected magic bytes for the declared content type.
4. **Early rejection**: If the file content does not match the declared type, the upload is rejected before any write occurs.

This prevents attackers from uploading executable files (JSP, EXE, PHP, etc.) with a spoofed image Content-Type header. The magic-byte check is a defense-in-depth layer that validates actual file content, not just client-supplied metadata.
