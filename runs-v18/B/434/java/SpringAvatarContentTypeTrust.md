## Verdict

Exploitable. The vulnerability permits an attacker to upload arbitrary file types by forging the client-supplied Content-Type header and original filename. The server validates only the header (which is trivially spoofable) and stores the file using the untrusted original filename, enabling both file-type bypass and potential path traversal.

## Source

- `avatar.getContentType()` (HTTP Content-Type header from the multipart request) at AvatarController.java:20
- `avatar.getOriginalFilename()` (HTTP filename from the multipart request) at AvatarStorage.java:15

Both values are client-supplied and not verified by the server.

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
    private static final Tika TIKA = new Tika();

    public AvatarController(AvatarStorage storage) {
        this.storage = storage;
    }

    @PostMapping("/profile/avatar")
    public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
        byte[] bytes = avatar.getBytes();
        String detectedType = TIKA.detect(bytes);

        if (!"image/png".equals(detectedType) && !"image/jpeg".equals(detectedType)) {
            return ResponseEntity.badRequest().body("unsupported avatar");
        }

        return ResponseEntity.ok(storage.store(avatar, detectedType));
    }
}
```

### File: AvatarStorage.java

```java
package cases.upload;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.web.multipart.MultipartFile;

public class AvatarStorage {
    private final Path storageDir;
    private static final Map<String, String> MIME_TO_EXT = new HashMap<>();

    static {
        MIME_TO_EXT.put("image/png", "png");
        MIME_TO_EXT.put("image/jpeg", "jpeg");
    }

    public AvatarStorage(Path storageDir) {
        this.storageDir = storageDir;
    }

    public String store(MultipartFile avatar, String detectedType) throws IOException {
        String extension = MIME_TO_EXT.get(detectedType);
        if (extension == null) {
            throw new IllegalArgumentException("Unsupported file type: " + detectedType);
        }

        String filename = UUID.randomUUID().toString() + "." + extension;
        Path target = storageDir.resolve(filename);
        avatar.transferTo(target);
        return target.getFileName().toString();
    }
}
```

## Explanation

The fix replaces client-supplied validation with content-based detection using Apache Tika. Instead of trusting `getContentType()` (an HTTP header), the controller now reads the actual file bytes and calls `TIKA.detect(bytes)` to determine the real file type from its binary signature (magic bytes). The detected type is validated against an allowlist of permitted MIME types (image/png, image/jpeg). The storage layer then generates a random UUID-based filename and derives its extension from a fixed MIME-to-extension map (`MIME_TO_EXT`), eliminating dependency on the client-supplied original filename. This prevents both file-type bypass (an attacker cannot fake being a PNG by forging headers) and path traversal attacks (the random UUID cannot contain directory separators). The storage signature now requires the validated `detectedType` parameter, ensuring untrusted values are never used for storage decisions.

## Behaviour changes

1. **Method signature change**: `AvatarStorage.store(MultipartFile)` now requires `AvatarStorage.store(MultipartFile, String detectedType)`. Callers must pass the content-detected type.

2. **Filename generation**: Files are now stored with random UUID filenames (e.g., `550e8400-e29b-41d4-a716-446655440000.png`) instead of the original client-supplied filename. This changes the response body: the API now returns the generated name instead of the original filename.

3. **Error handling**: If the detected type is not in the allowlist, an `IllegalArgumentException` is thrown instead of silently storing an unsupported file. This is a necessary security hardening.

4. **Dependency added**: Apache Tika (`org.apache.tika:tika-core`) must be added to the project's Maven/Gradle dependencies. No version constraint is enforced by this guidance; the dependency version must be managed through SCA/dependency-check tooling.

5. **Implicit argument behaviour**: The `TIKA.detect()` method reads the file bytes to determine type; no default parameters are left implicit. All type detection is explicit and content-based.

## Verification

The fix was reviewed for syntax correctness and logical soundness against the CWE-434 guidance. Key validations:

- All imports are standard Java, Spring Framework, Apache Tika, or java.nio/java.util (all commonly available in Spring Boot projects).
- The Tika API call `TIKA.detect(bytes)` correctly identifies file types from byte content.
- The MIME-to-extension map is correctly populated and checked before use.
- The UUID-based filename generation cannot contain path traversal sequences.
- The method signature change is correctly propagated to the call site in AvatarController.

No compiler was run in this environment due to unavailable transitive dependencies (Spring and Tika), but the code structure and method calls align with their documented APIs. A full compilation within a Maven/Gradle project with dependencies declared would be required for final verification before merge.

## Assumptions

- **Library available**: Apache Tika (`org.apache.tika:tika-core`) is assumed to be a valid dependency for the project. If not already present, it must be added to `pom.xml` or `build.gradle`.
- **Storage directory outside webroot**: The guidance assumes `storageDir` is configured to point to a location outside `src/main/resources/static`, `webapp`, or any Spring-served directory. This is not enforced in code but is necessary to prevent the application from serving uploaded files directly via HTTP. Configuration of `storageDir` is the responsibility of the application setup.
- **Spring Boot 2.0+**: The fix assumes Spring Framework 5.0+ and Spring Boot 2.0+ where `MultipartFile` and annotations (`@PostMapping`, `@RestController`) are present in their current form.

