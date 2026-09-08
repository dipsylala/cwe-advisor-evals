## Verdict

Confirmed. The upload handler decides whether to accept a file solely from the client-supplied `Content-Type` multipart header (`file.getContentType()`), checked against an allowlist. That header is attacker-controlled: a request can declare `image/png` while the part body is a JSP, an HTML page, a script, or an executable, and the value is never verified against the file's actual bytes. The declared type is also used to pick the stored extension, so a spoofed `image/png` declaration lands the payload with a `.png` extension in the upload directory — the dangerous-type check is bypassable with a single header change.

## Source

`file` (the `MultipartFile` bound from the incoming `multipart/form-data` request body via `@RequestParam("file")` in `uploadImage`), specifically its attacker-controlled `getContentType()` metadata and its `getInputStream()` content, both taken from the untrusted HTTP request.

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

    private static final byte[] PNG_SIGNATURE =
            {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};

    @PostMapping("/api/images")
    public ResponseEntity<String> uploadImage(@RequestParam("file") MultipartFile file) throws IOException {
        String declaredContentType = file.getContentType();
        if (declaredContentType == null || !ALLOWED_CONTENT_TYPES.contains(declaredContentType)) {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Unsupported image type");
        }

        // The multipart Content-Type header is attacker-controlled and is not
        // proof of what the bytes actually are, so the accept/reject decision
        // and the stored extension are both re-derived from the file's magic
        // bytes rather than trusted from the client-declared header.
        byte[] content = file.getBytes();
        String detectedContentType = detectImageContentType(content);
        if (detectedContentType == null || !ALLOWED_CONTENT_TYPES.contains(detectedContentType)) {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Unsupported image type");
        }

        // Filename generation is already safe: a random UUID with the extension
        // looked up from a fixed map keyed by the magic-byte-detected content type.
        String extension = EXTENSION_BY_CONTENT_TYPE.get(detectedContentType);
        String storedName = UUID.randomUUID() + extension;
        Path destination = UPLOAD_DIR.resolve(storedName);

        Files.write(destination, content, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        return ResponseEntity.ok(storedName);
    }

    /**
     * Identifies the image format from its leading bytes (file signature / magic
     * number) rather than any client-supplied metadata. Returns null when the
     * content does not match a known, allowed image signature.
     */
    private static String detectImageContentType(byte[] content) {
        if (content.length >= PNG_SIGNATURE.length && startsWith(content, PNG_SIGNATURE)) {
            return "image/png";
        }
        if (content.length >= 3
                && (content[0] & 0xFF) == 0xFF
                && (content[1] & 0xFF) == 0xD8
                && (content[2] & 0xFF) == 0xFF) {
            return "image/jpeg";
        }
        return null;
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }
}
```

## Explanation

The vulnerable code trusted `MultipartFile.getContentType()` — a value copied verbatim from the request's `Content-Type` part header — as if it described the file's real contents, and used it both as the security gate and as the source of the stored file extension. Neither Spring nor the servlet container validates that header against the bytes that follow it, so any client can set it to `image/png` while uploading arbitrary content (for example a `.jsp`/`.php` payload or an HTML page with an embedded script), producing a file that passes the allowlist and is written to disk with an image extension.

The fix keeps the existing declared-type check as a cheap early rejection, then re-derives the actual type from the file's magic bytes (the PNG signature `89 50 4E 47 0D 0A 1A 0A` and the JPEG signature `FF D8 FF`) before accepting the upload. Both the accept/reject decision and the extension chosen for the stored filename now come from this magic-byte detection rather than from client-supplied metadata, so a mislabeled non-image payload is rejected regardless of what `Content-Type` the client sends. The file is read once into memory with `MultipartFile.getBytes()` and that same byte array is both inspected and written via `Files.write`, avoiding a second, inconsistent read of the underlying stream. The upload directory, random UUID naming, and REST contract are unchanged.
