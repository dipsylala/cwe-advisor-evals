## Verdict
The finding is valid. The upload endpoint validates only the `Content-Type` header without checking the actual file content (magic bytes). An attacker can upload a malicious file with a spoofed MIME type to bypass the allowlist and achieve arbitrary file upload.

## Source
The vulnerability exists at line 45 in `ImageUploadController.java`. The code accepts the client-supplied `Content-Type` header at line 33 and uses it to determine the stored file extension at line 40-41. However, it never verifies that the actual file bytes match the declared MIME type. An attacker can send a `.exe` payload with `Content-Type: image/png` and it will be stored as `.png` with executable content.

## Fix
Add magic byte validation to confirm actual file content matches the declared MIME type before accepting the upload.

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

    // Magic bytes for PNG: 89 50 4E 47
    private static final byte[] PNG_MAGIC = {(byte) 0x89, 0x50, 0x4E, 0x47};
    
    // Magic bytes for JPEG: FF D8 FF
    private static final byte[] JPEG_MAGIC = {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF};

    @PostMapping("/api/images")
    public ResponseEntity<String> uploadImage(@RequestParam("file") MultipartFile file) throws IOException {
        String contentType = file.getContentType();
        if (contentType == null || !ALLOWED_CONTENT_TYPES.contains(contentType)) {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Unsupported image type");
        }

        // Verify actual file content matches declared content type using magic bytes
        if (!isValidImageMagicBytes(file, contentType)) {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("File content does not match declared type");
        }

        // Filename generation is already safe: a random UUID with the extension
        // looked up from a fixed map keyed by the declared content type.
        String extension = EXTENSION_BY_CONTENT_TYPE.get(contentType);
        String storedName = UUID.randomUUID() + extension;
        Path destination = UPLOAD_DIR.resolve(storedName);

        Files.copy(file.getInputStream(), destination, StandardCopyOption.REPLACE_EXISTING);

        return ResponseEntity.ok(storedName);
    }

    private boolean isValidImageMagicBytes(MultipartFile file, String contentType) throws IOException {
        byte[] buffer = new byte[4];
        try (InputStream is = file.getInputStream()) {
            int bytesRead = is.read(buffer);
            if (bytesRead < 2) {
                return false;
            }
            
            if ("image/png".equals(contentType)) {
                return bytesRead >= PNG_MAGIC.length && startsWith(buffer, PNG_MAGIC);
            } else if ("image/jpeg".equals(contentType)) {
                return bytesRead >= JPEG_MAGIC.length && startsWith(buffer, JPEG_MAGIC);
            }
        }
        return false;
    }

    private boolean startsWith(byte[] buffer, byte[] magic) {
        if (buffer.length < magic.length) {
            return false;
        }
        for (int i = 0; i < magic.length; i++) {
            if (buffer[i] != magic[i]) {
                return false;
            }
        }
        return true;
    }
}
```

## Explanation
The fix adds two validation methods:

1. `isValidImageMagicBytes()` reads the first 4 bytes of the uploaded file and compares them against known magic byte signatures for PNG (0x89504E47) and JPEG (0xFFD8FF). The content type must match the actual file content signature before upload proceeds.

2. `startsWith()` is a helper method that safely checks if the buffer begins with the expected magic sequence.

This prevents spoofed MIME types from allowing dangerous file types through. An attacker attempting to upload a `.exe` while claiming `Content-Type: image/png` will fail the magic byte check and be rejected, even if the filename is randomized and stored outside the web root. The fix preserves the existing safe filename generation (UUID-based) and directory isolation.
