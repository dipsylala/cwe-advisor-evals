## Verdict

**Real vulnerability.** Line 20 of AvatarController.java validates file uploads by trusting `avatar.getContentType()`, which is a client-supplied HTTP header that cannot be verified and is trivially forged. An attacker can upload an executable script, web shell, or other dangerous file type while setting the Content-Type header to "image/png" or "image/jpeg", bypassing the validation. The downstream code in AvatarStorage uses `getOriginalFilename()` (also client-supplied) as the storage path, allowing the attacker to control both the file extension and potentially the stored filename. If the storage directory is served by the web application, the attacker's file can be executed by the server.

## Source

**AvatarController.java, line 20:** `String contentType = avatar.getContentType();`

The content-type validation that follows checks only the client-supplied HTTP header. The MultipartFile is then passed to `AvatarStorage.store()`, which writes it using the original filename from the request.

**AvatarStorage.java, line 18:** `Path target = storageDir.resolve(avatar.getOriginalFilename());`

The original filename (client-supplied) is used directly as the storage path. This enables path traversal and allows the attacker to choose the file extension, determining how the stored file is later served or executed.

## Fix

### 1. Add dependency: Apache Tika

In `pom.xml`, add:
```xml
<dependency>
    <groupId>org.apache.tika</groupId>
    <artifactId>tika-core</artifactId>
    <version>2.9.0</version>
</dependency>
```

(Confirm the version against SCA/dependency-check tooling before merging; the guidance specifies this as a commonly used maintained option, but version selection should be verified against current advisories.)

### 2. Updated AvatarController.java

```java
package cases.upload;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
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
    private static final Set<String> ALLOWED_TYPES = Set.of("image/png", "image/jpeg");
    private static final Map<String, String> MIME_TO_EXT = new HashMap<>();

    static {
        MIME_TO_EXT.put("image/png", ".png");
        MIME_TO_EXT.put("image/jpeg", ".jpg");
    }

    public AvatarController(AvatarStorage storage) {
        this.storage = storage;
    }

    @PostMapping("/profile/avatar")
    public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
        byte[] bytes = avatar.getBytes();

        // Detect actual file type from content bytes, not client header
        String detectedType = tika.detect(bytes);
        if (!ALLOWED_TYPES.contains(detectedType)) {
            return ResponseEntity.badRequest().body("unsupported avatar");
        }

        // Map detected type to safe extension from allowlist
        String extension = MIME_TO_EXT.get(detectedType);
        
        return ResponseEntity.ok(storage.store(bytes, extension));
    }
}
```

### 3. Updated AvatarStorage.java

```java
package cases.upload;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.UUID;

public class AvatarStorage {
    private final Path storageDir;

    public AvatarStorage(Path storageDir) {
        this.storageDir = storageDir;
    }

    public String store(byte[] imageBytes, String extension) throws IOException {
        // Generate a random filename using UUID; extension comes from allowlist
        String filename = UUID.randomUUID().toString() + extension;
        Path target = storageDir.resolve(filename);
        
        // Write with CREATE_NEW to prevent overwrite attacks
        Files.write(target, imageBytes, StandardOpenOption.CREATE_NEW);
        
        return filename;
    }
}
```

## Explanation

The original code trusts two client-supplied values: the Content-Type header (via `getContentType()`) and the original filename. Both can be forged by an attacker. The fix replaces both with server-controlled values:

1. **Content detection:** Instead of checking the HTTP header, Apache Tika inspects the actual file bytes to detect the real MIME type. This prevents an attacker from uploading an executable while claiming it is an image.

2. **Allowlist validation:** The detected type is validated against `ALLOWED_TYPES`, a server-controlled set of permitted types. Only image/png and image/jpeg are permitted.

3. **Canonical value selection:** After validation, the code selects the canonical extension from `MIME_TO_EXT` (a fixed allowlist map) rather than using the client's filename. This ensures the stored filename's extension cannot be exploited to make the server treat the file differently than intended.

4. **Random filename:** A UUID-based filename is generated for storage, preventing both path traversal attacks (via `..` sequences in the original filename) and filename collisions. The attacker no longer controls the stored path or extension.

5. **Secure write:** `StandardOpenOption.CREATE_NEW` ensures the write fails if the file already exists, preventing overwrite attacks.

6. **Taint break:** The controller now passes only the validated `extension` (from the allowlist) and the raw `imageBytes` to storage, severing the taint chain from the original request values.

The guidance also recommends re-encoding images (decode and re-save with `javax.imageio.ImageIO`) to strip embedded scripts or malicious metadata from image files; this implementation validates the content, but production code should add that hardening step for defense-in-depth.

## Behaviour changes

- **Detection method:** Uploads now use byte-content inspection (Tika) instead of client-supplied Content-Type header.
- **Filename:** Stored files use randomly generated UUID-based names instead of the original filename; the extension is mapped from the detected type's allowlist entry.
- **Rejection:** Files with mismatched extension/content (e.g., a `.txt` file masquerading as `image/png`) are now rejected at the controller level, before storage.
- **Path resolution:** Filenames are no longer sourced from user input, eliminating path traversal vulnerabilities.
- **Write atomicity:** Writes use `CREATE_NEW`, failing if a collision occurs rather than silently overwriting.
- **API change:** `AvatarStorage.store()` signature changes from `MultipartFile` to `byte[]` and `String extension`, making the contract explicit that the extension is server-controlled after validation.
