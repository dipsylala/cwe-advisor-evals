## Verdict

Exploitable. The application validates the uploaded file type using only the client-supplied `Content-Type` HTTP header without inspecting actual file bytes. An attacker can upload a malicious file (e.g., executable, JSP, script) with a forged `Content-Type: image/png` header to bypass the validation check at line 21. The file is then stored using the client-supplied original filename, enabling both file-type evasion and potential path traversal.

## Source

`avatar.getContentType()` at line 20 of AvatarController.java. This method returns the `Content-Type` HTTP header from the client request, which is untrusted and can be forged. The source is attacker-controlled.

## Fix

**Vulnerable Code:**

```java
@PostMapping("/profile/avatar")
public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
    String contentType = avatar.getContentType();  // VULNERABLE: trusts client-supplied header
    if (!"image/png".equals(contentType) && !"image/jpeg".equals(contentType)) {
        return ResponseEntity.badRequest().body("unsupported avatar");
    }

    return ResponseEntity.ok(storage.store(avatar));
}
```

**Fixed AvatarController.java:**

```java
package cases.upload;

import java.io.IOException;
import java.util.Set;
import java.util.UUID;
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
    private static final Set<String> ALLOWED_TYPES = Set.of("image/png", "image/jpeg");

    public AvatarController(AvatarStorage storage) {
        this.storage = storage;
    }

    @PostMapping("/profile/avatar")
    public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
        // Detect actual content type from file bytes, not from client-supplied header
        byte[] bytes = avatar.getBytes();
        String detectedType = tika.detect(bytes);
        
        // Validate against allowlist of approved types
        if (!ALLOWED_TYPES.contains(detectedType)) {
            return ResponseEntity.badRequest().body("unsupported avatar");
        }

        // Generate safe filename and store
        String safeFilename = UUID.randomUUID().toString();
        return ResponseEntity.ok(storage.store(bytes, safeFilename, detectedType));
    }
}
```

**Fixed AvatarStorage.java** (required update to complete the fix):

```java
package cases.upload;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public class AvatarStorage {
    private final Path storageDir;
    private static final java.util.Map<String, String> MIME_TO_EXT = 
        java.util.Map.of(
            "image/png", ".png",
            "image/jpeg", ".jpg"
        );

    public AvatarStorage(Path storageDir) {
        this.storageDir = storageDir;
    }

    public String store(byte[] bytes, String filename, String mimeType) throws IOException {
        // Derive extension from detected MIME type, not from original filename
        String extension = MIME_TO_EXT.getOrDefault(mimeType, "");
        
        // Construct safe path with generated filename and detected extension
        Path target = storageDir.resolve(filename + extension);
        
        // Write with CREATE_NEW to prevent overwriting existing files
        Files.write(target, bytes, StandardOpenOption.CREATE_NEW);
        
        return target.getFileName().toString();
    }
}
```

**Dependency Addition (pom.xml):**

Add Apache Tika for content-type detection:
```xml
<dependency>
    <groupId>org.apache.tika</groupId>
    <artifactId>tika-core</artifactId>
</dependency>
```

The version must be confirmed against your dependency management and SCA tooling.

## Explanation

The fix replaces client-supplied header validation with actual content inspection using Apache Tika, which analyzes file bytes to detect the true MIME type. The controller reads the full file bytes and passes them through `tika.detect()` before validating against the allowlist. Only bytes matching an approved type proceed to storage. The storage layer now accepts pre-validated bytes and a server-generated UUID-based filename, eliminating both the header-forgery vector and the original-filename risk. The extension is derived from the detected type (not the original filename) using a fixed allowlist map, preventing an attacker from choosing how the file will be served through the extension.

## Behaviour changes

**Method signature change in AvatarStorage.store()**: The method changes from accepting `MultipartFile avatar` to accepting `byte[] bytes, String filename, String mimeType`. The controller now handles validation and file reading, passing only validated data downstream. This is necessary because the original signature tied validation to the upload object, making it impossible to enforce content-based detection.

**Tika initialization overhead**: The controller instantiates a `Tika` object on each request. For production, consider caching this as a Spring bean to reduce object allocation overhead. Current behavior is correct but not optimal for high-volume upload endpoints.

**Extension derivation from MIME type**: The extension is now derived from the detected MIME type via a fixed allowlist map rather than from the original filename. This prevents an attacker from using a `.php` or other dangerous extension to influence how the stored file is served. The allowlist ensures only approved extensions are used; an unrecognized MIME type will produce an empty extension (safe fail).

**File write mode**: The storage layer now uses `StandardOpenOption.CREATE_NEW`, which atomically fails if the target file already exists. The original `transferTo()` with default options would silently overwrite. This prevents collision attacks and is a hardening improvement; it may require handling `FileAlreadyExistsException` if the random UUID generation has a collision (vanishingly unlikely, but possible in pathological scenarios).
