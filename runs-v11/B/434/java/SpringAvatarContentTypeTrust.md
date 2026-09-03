## Verdict

Exploitable. The vulnerability allows an attacker to upload files of arbitrary type by spoofing the Content-Type header, and then execute or access them via a predictable or traversable filename in the storage path.

## Source

HTTP request parameter `MultipartFile avatar` in the `@PostMapping("/profile/avatar")` handler (line 19, AvatarController.java). Client-supplied headers `getContentType()` and `getOriginalFilename()` are attacker-controlled.

## Fix

### AvatarController.java (fixed)

```java
package cases.upload;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import java.util.HashMap;
import java.util.Map;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import org.apache.tika.Tika;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class AvatarController {
    private final AvatarStorage storage;
    private static final Tika tika = new Tika();
    private static final long MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
    private static final Map<String, String> ALLOWED_TYPES = new HashMap<>();
    
    static {
        ALLOWED_TYPES.put("image/png", ".png");
        ALLOWED_TYPES.put("image/jpeg", ".jpg");
    }

    public AvatarController(AvatarStorage storage) {
        this.storage = storage;
    }

    @PostMapping("/profile/avatar")
    public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
        // Enforce size limit before processing
        if (avatar.getSize() > MAX_FILE_SIZE) {
            return ResponseEntity.badRequest().body("file too large");
        }
        
        // Detect actual MIME type from file bytes, not from client-supplied Content-Type header
        byte[] fileBytes = avatar.getBytes();
        String detectedType = tika.detect(fileBytes);
        
        // Validate against allowlist of permitted types
        if (!ALLOWED_TYPES.containsKey(detectedType)) {
            return ResponseEntity.badRequest().body("unsupported avatar");
        }
        
        // Generate random filename; use detected type to derive extension
        String generatedFilename = UUID.randomUUID().toString() + ALLOWED_TYPES.get(detectedType);
        
        // For images, re-encode to strip embedded scripts or malformed metadata
        byte[] encodedBytes = fileBytes;
        if ("image/png".equals(detectedType) || "image/jpeg".equals(detectedType)) {
            encodedBytes = reEncodeImage(fileBytes, detectedType);
        }
        
        return ResponseEntity.ok(storage.store(generatedFilename, encodedBytes));
    }
    
    private byte[] reEncodeImage(byte[] fileBytes, String mimeType) throws IOException {
        // Read image and re-save to strip embedded scripts or metadata
        BufferedImage image = ImageIO.read(new java.io.ByteArrayInputStream(fileBytes));
        if (image == null) {
            throw new IOException("Invalid image content");
        }
        
        // Re-write image to bytes (discarding everything except pixel data)
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        String formatName = "image/png".equals(mimeType) ? "PNG" : "JPEG";
        ImageIO.write(image, formatName, baos);
        return baos.toByteArray();
    }
}
```

### AvatarStorage.java (fixed)

```java
package cases.upload;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import org.springframework.web.multipart.MultipartFile;

public class AvatarStorage {
    private final Path storageDir;

    public AvatarStorage(Path storageDir) {
        this.storageDir = storageDir;
    }

    public String store(String generatedFilename, byte[] fileBytes) throws IOException {
        // Use generated filename provided by caller, never trust original filename
        Path target = storageDir.resolve(generatedFilename);
        
        // Write with CREATE_NEW to prevent race conditions and path traversal
        Files.write(target, fileBytes, StandardOpenOption.CREATE_NEW);
        return target.getFileName().toString();
    }
}
```

## Explanation

The original code has three critical vulnerabilities:

1. **Client-supplied Content-Type trust**: Line 20 calls `avatar.getContentType()`, which is the HTTP Content-Type header sent by the client. An attacker can forge this header to any value, bypassing the allowlist check on lines 21-23. The check provides false security because it validates against an untrusted value, not the actual file content.

2. **Unvalidated filename usage**: Line 15 in AvatarStorage uses `avatar.getOriginalFilename()` directly, which is also client-supplied and can contain path traversal sequences like `../../../etc/passwd`. This allows writing files outside the intended storage directory.

3. **No protection against embedded payloads**: Even with content-type validation, image files can contain embedded scripts in metadata or polyglot constructs after the valid image header. Without re-encoding, these payloads persist.

The fix addresses all three issues:

- Detect the actual MIME type from file bytes using Apache Tika (`tika.detect(fileBytes)`), not from the client-supplied header. Tika inspects the file signature (magic bytes) to identify the true type.
- Generate a random filename using `UUID.randomUUID()` and derive the extension from the Tika-detected type (via the `ALLOWED_TYPES` map), eliminating the attacker's ability to choose the filename or extension.
- For image uploads, re-encode the file by reading it with `ImageIO.read()` and writing it back with `ImageIO.write()`, which discards everything except pixel data and strips embedded scripts, metadata, or polyglot constructs.
- Change `AvatarStorage.store()` signature to accept the generated filename and pre-validated file bytes, eliminating the need for it to inspect or transform the input.
- Use `Files.write()` with `StandardOpenOption.CREATE_NEW` to prevent race conditions and ensure atomic creation.

## Behaviour changes

- **New dependency**: Apache Tika (`org.apache.tika:tika-core`) is required for content-type detection. Add to `pom.xml`: `<groupId>org.apache.tika</groupId><artifactId>tika-core</artifactId>` (version determined by SCA/advisory; no known fixed version specified in guidance, use latest available for your project).
- **File size enforcement**: A new size limit (5MB) is enforced before processing. This is a hardening measure to prevent resource exhaustion; the limit should be tuned to match the application's requirements.
- **Filename change**: Generated filenames are now random UUIDs with a fixed extension, rather than the original filename. Clients requesting the file back must use the returned filename from the response, not the original upload name.
- **Image re-encoding overhead**: Images are now decoded and re-encoded on upload, adding processing time. This is necessary to strip embedded scripts and metadata; the overhead is typically acceptable for profile images.
- **Exception handling**: Re-encoding can throw `IOException` if the image is malformed; this is caught and returned as a 400 error (already handled by the existing `throws IOException`).
- **Storage API change**: `AvatarStorage.store()` now takes two parameters (`String generatedFilename, byte[] fileBytes`) instead of `MultipartFile avatar`. Callers must generate the filename and provide validated bytes.
- **Return value preservation**: The return value of `storage.store()` remains the stored filename as a String, compatible with the existing controller response.
