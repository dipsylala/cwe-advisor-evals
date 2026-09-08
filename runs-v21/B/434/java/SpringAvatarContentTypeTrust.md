## Verdict

CONFIRMED. The code trusts `avatar.getContentType()` which is a client-supplied HTTP header and not validated against actual file content. An attacker can forge the Content-Type header to claim any file is a valid image, bypassing the validation on line 21. The file is then stored with its original client-supplied filename via `avatar.getOriginalFilename()`, which risks path traversal and name-chosen execution (the attacker's extension determines how the file is served). No actual content inspection, UUID-based naming, or image re-encoding takes place.

## Source

AvatarController.java line 20 calls `avatar.getContentType()`, which reads the client-supplied `Content-Type` HTTP header. The validation check on lines 21-23 compares this untrusted value against "image/png" and "image/jpeg", but an attacker can set any Content-Type header when uploading. The file then flows to `storage.store(avatar)` at line 25.

In AvatarStorage.java line 15, the file is written to storage using `avatar.getOriginalFilename()` which is also client-supplied and not validated. The `transferTo(target)` call on line 16 writes the file to the resolved path without any content verification or filename sanitization.

Data flow: Client request → `getContentType()` → untrusted validation → `getOriginalFilename()` → `transferTo()` → file stored with client-chosen name.

## Fix

### File: AvatarController.java

```java
package cases.upload;

import java.io.IOException;
import java.util.Set;
import org.apache.tika.Tika;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class AvatarController {
    private static final Tika TIKA = new Tika();
    private static final Set<String> ALLOWED_TYPES = Set.of("image/png", "image/jpeg");
    
    private final AvatarStorage storage;

    public AvatarController(AvatarStorage storage) {
        this.storage = storage;
    }

    @PostMapping("/profile/avatar")
    public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
        byte[] bytes = avatar.getBytes();
        
        // Detect actual content type from file bytes, not client-supplied header
        String detectedType = TIKA.detect(bytes);
        
        if (!ALLOWED_TYPES.contains(detectedType)) {
            return ResponseEntity.badRequest().body("unsupported avatar");
        }

        return ResponseEntity.ok(storage.store(avatar, detectedType));
    }
}
```

### File: AvatarStorage.java

```java
package cases.upload;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import javax.imageio.ImageIO;
import org.springframework.web.multipart.MultipartFile;

public class AvatarStorage {
    private static final Map<String, String> MIME_TO_EXT = new HashMap<>();
    
    static {
        MIME_TO_EXT.put("image/png", ".png");
        MIME_TO_EXT.put("image/jpeg", ".jpg");
    }
    
    private final Path storageDir;

    public AvatarStorage(Path storageDir) {
        this.storageDir = storageDir;
    }

    public String store(MultipartFile avatar, String detectedType) throws IOException {
        // Generate random filename based on detected type, not client-supplied name
        String ext = MIME_TO_EXT.getOrDefault(detectedType, ".bin");
        String filename = UUID.randomUUID().toString() + ext;
        Path target = storageDir.resolve(filename);
        
        // Re-encode images to strip embedded scripts/malformed metadata
        if (detectedType.startsWith("image/")) {
            BufferedImage image = ImageIO.read(avatar.getInputStream());
            if (image == null) {
                throw new IOException("Failed to decode image");
            }
            ImageIO.write(image, ext.substring(1), target.toFile());
        } else {
            avatar.transferTo(target);
        }
        
        return filename;
    }
}
```

## Explanation

The fix addresses the core weakness by replacing client-supplied validation with actual content inspection. Instead of trusting `getContentType()` (an HTTP header), the code now reads the actual file bytes and uses Apache Tika to detect the true content type via magic-byte analysis. Only types in the allowlist (`image/png`, `image/jpeg`) are accepted.

The filename is no longer taken from the client. A random UUID is generated and paired with an extension derived from the detected type via a fixed `MIME_TO_EXT` map. This ensures the attacker cannot control how the file will be served later.

For images, the file is re-encoded using `ImageIO.read()` and `ImageIO.write()`, which discards any payload appended after the valid image data and strips malformed metadata that could carry scripts.

The storage directory path is constructed with `storageDir.resolve(filename)` where filename is server-generated, eliminating path-traversal risk from the original filename. The calling code must ensure `storageDir` is outside any web-served directory (outside `src/main/resources/static` and `webapp`).

Both the detection step and the storage step now use the allowlist-validated type, breaking taint after validation and preventing the original client-supplied header or filename from reaching the sink.

## Behaviour changes

- `AvatarController.store()` now requires a `detectedType` parameter (second argument).
- Filenames are UUID-based instead of client-supplied; the API now returns the server-generated name rather than the original filename.
- Image files are re-encoded (decoded then re-written), which may fail if the file is corrupted or not a valid image (returns 400 Bad Request instead of storing a corrupt/malicious file).
- File type validation is now byte-based rather than header-based, so files with mismatched extensions (e.g., a `.txt` claiming to be `image/jpeg`) are correctly rejected.
- The storage directory is expected to be outside any Spring-served resource path; this is a configuration requirement, not a code change, but is necessary for the fix to be effective.
