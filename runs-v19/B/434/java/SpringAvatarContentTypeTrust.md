## Verdict

Exploitable

## Source

HTTP POST request body containing the uploaded file via `MultipartFile` parameter at AvatarController line 19.

## Sink

Line 20: `avatar.getContentType()` (client-supplied HTTP header, not content-validated)
Line 15 in AvatarStorage: `avatar.getOriginalFilename()` (client-supplied, not sanitized)
Line 16 in AvatarStorage: `avatar.transferTo(target)` (writes file using untrusted filename to storage)

## Data Flow

1. Client sends POST request with `MultipartFile` containing arbitrary binary data and forged Content-Type header
2. AvatarController extracts Content-Type header via `avatar.getContentType()` - this trusts the client-supplied HTTP header without inspecting actual file bytes
3. Validation at line 21 checks only the header, not the actual content
4. File passed to AvatarStorage.store() with no content verification
5. AvatarStorage uses `avatar.getOriginalFilename()` (client-controlled) as the storage filename
6. `transferTo()` writes the file with its original, untrusted filename to the storage directory
7. An attacker can upload a malicious script (e.g., Java .class file, JSP, or shell) with Content-Type: image/png and any filename, bypass the check, and store it with a name of their choosing

The attack succeeds because: (a) Content-Type validation trusts a client-supplied header instead of inspecting bytes, (b) the original filename is used as-is, enabling path traversal or choosing the execution filename, and (c) the file is stored with its original name and extension rather than a generated one.

## Fix

### File: AvatarController.java

```java
package cases.upload;

import java.io.IOException;
import org.apache.tika.Tika;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class AvatarController {
    private final AvatarStorage storage;
    private final Tika tika = new Tika();

    public AvatarController(AvatarStorage storage) {
        this.storage = storage;
    }

    @PostMapping("/profile/avatar")
    public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
        // Detect actual content type from file bytes, not from client-supplied header
        byte[] fileBytes = avatar.getBytes();
        String detectedContentType = tika.detect(fileBytes);
        
        // Validate against allowlist of permitted image types
        if (!"image/png".equals(detectedContentType) && !"image/jpeg".equals(detectedContentType)) {
            return ResponseEntity.badRequest().body("unsupported avatar");
        }

        return ResponseEntity.ok(storage.store(avatar, detectedContentType));
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
    private final Path storageDir;
    private static final Map<String, String> MIME_TO_EXT = new HashMap<>();

    static {
        MIME_TO_EXT.put("image/png", ".png");
        MIME_TO_EXT.put("image/jpeg", ".jpg");
    }

    public AvatarStorage(Path storageDir) {
        this.storageDir = storageDir;
    }

    public String store(MultipartFile avatar, String detectedContentType) throws IOException {
        // Generate a random filename using UUID
        String randomName = UUID.randomUUID().toString();
        
        // Derive the extension from the detected content type, not from client-supplied filename
        String extension = MIME_TO_EXT.get(detectedContentType);
        if (extension == null || extension.isEmpty()) {
            throw new IOException("Unsupported content type: " + detectedContentType);
        }
        
        String filename = randomName + extension;
        Path target = storageDir.resolve(filename);
        
        // Re-encode images to strip embedded scripts or malformed metadata
        byte[] fileBytes = avatar.getBytes();
        if ("image/png".equals(detectedContentType) || "image/jpeg".equals(detectedContentType)) {
            BufferedImage image = ImageIO.read(new java.io.ByteArrayInputStream(fileBytes));
            if (image == null) {
                throw new IOException("Failed to decode image");
            }
            // Re-encode the image, which strips any payload after the image data
            ImageIO.write(image, detectedContentType.substring(6), Files.newOutputStream(target, StandardOpenOption.CREATE_NEW));
        } else {
            // For non-image types, write as-is with atomic CREATE_NEW to prevent race conditions
            Files.write(target, fileBytes, StandardOpenOption.CREATE_NEW);
        }
        
        return filename;
    }
}
```

## Explanation

The fixed code replaces three distinct vulnerability points. First, it eliminates the Content-Type validation weakness by calling `tika.detect(fileBytes)` to inspect the actual file bytes instead of trusting the client-supplied `getContentType()` header. Second, it generates a random filename using `UUID.randomUUID()` and derives the file extension from the detected MIME type through a fixed allowlist map, rather than using the client-supplied `getOriginalFilename()` which may contain path traversal sequences or attacker-chosen names. Third, it re-encodes images through `ImageIO.read()` and `ImageIO.write()` to strip any embedded scripts or malformed metadata that raw bytes may carry. The method signature change to `store(MultipartFile avatar, String detectedContentType)` passes the server-validated type, breaking taint after allowlist validation as required. Using `StandardOpenOption.CREATE_NEW` ensures atomic file creation and fails if the file already exists, preventing race conditions. All three changes work together to enforce that the stored filename and extension are server-controlled and the content is verified before storage.

## Behaviour changes

- **Method signature change**: `AvatarStorage.store()` now accepts a second parameter `detectedContentType`. The controller now calls this method with the Tika-detected content type instead of passing the file alone. This is required to ensure the validated, server-controlled type is used for storage decisions. The return value remains unchanged (a filename string).
- **Filename generation**: Files are now stored with a UUID-based random name instead of the original filename. This eliminates path traversal risks and prevents the attacker from choosing the storage filename or extension. The stored file is accessible only by the returned filename that the application tracks, not by guessing or manipulating the original upload name.
- **Image re-encoding**: For PNG and JPEG files, the code now decodes and re-encodes the image through `ImageIO`, which strips any payload appended after the image data (e.g., a polyglot file that is a valid PNG with an embedded script). Non-image types (if added to the allowlist in the future) are written directly but with atomic `CREATE_NEW` semantics instead of overwriting.
- **Atomic file creation**: Both image and non-image storage paths now use `StandardOpenOption.CREATE_NEW`, which fails if the file already exists. This prevents race conditions where two concurrent uploads could collide on the same filename (extremely unlikely with UUID but a good hardening practice).
- **Error handling**: If Tika cannot decode an image that passed the content-type allowlist, or if the content type is not in the MIME_TO_EXT map, an IOException is thrown with a descriptive message. This fails closed rather than silently accepting invalid data.
- **Exception propagation**: The `throws IOException` clause remains, so callers receive exceptions if image decoding or file I/O fails, consistent with the original contract.

No other behavior changes. The controller still returns the same response structure (ResponseEntity with a success message or 400 error), and the storage directory path resolution works identically.
