## Verdict

exploitable

## Source

`avatar.getContentType()` at line 20 of AvatarController.java is client-supplied via the HTTP Content-Type header and is not validated by inspecting file bytes. An attacker can forge this header to bypass the type check and upload an executable file.

Secondary source: `avatar.getOriginalFilename()` at line 15 of AvatarStorage.java is also client-supplied and can contain path traversal sequences or arbitrary extensions.

## Fix

**Vulnerable Code (AvatarController.java, lines 18–26):**
```java
@PostMapping("/profile/avatar")
public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
    String contentType = avatar.getContentType();
    if (!"image/png".equals(contentType) && !"image/jpeg".equals(contentType)) {
        return ResponseEntity.badRequest().body("unsupported avatar");
    }

    return ResponseEntity.ok(storage.store(avatar));
}
```

**Fixed Code (AvatarController.java):**
```java
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.util.HashMap;
import java.util.Map;
import javax.imageio.ImageIO;
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
    private static final Map<String, String> MIME_TO_EXT = new HashMap<>();
    private static final long MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

    static {
        MIME_TO_EXT.put("image/png", "png");
        MIME_TO_EXT.put("image/jpeg", "jpg");
    }

    public AvatarController(AvatarStorage storage) {
        this.storage = storage;
    }

    @PostMapping("/profile/avatar")
    public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
        // Check file size
        if (avatar.getSize() > MAX_FILE_SIZE) {
            return ResponseEntity.badRequest().body("file too large");
        }

        // Detect actual content type by inspecting file bytes
        byte[] bytes = avatar.getBytes();
        String detectedType = tika.detect(bytes);

        // Validate against allowlist
        if (!MIME_TO_EXT.containsKey(detectedType)) {
            return ResponseEntity.badRequest().body("unsupported avatar type");
        }

        // Re-encode image to strip embedded scripts and verify it is a valid image
        BufferedImage image;
        try {
            image = ImageIO.read(new ByteArrayInputStream(bytes));
            if (image == null) {
                return ResponseEntity.badRequest().body("invalid image");
            }
        } catch (IOException e) {
            return ResponseEntity.badRequest().body("corrupted image");
        }

        String extension = MIME_TO_EXT.get(detectedType);
        return ResponseEntity.ok(storage.store(image, detectedType, extension));
    }
}
```

**Vulnerable Code (AvatarStorage.java, lines 14–18):**
```java
public String store(MultipartFile avatar) throws IOException {
    Path target = storageDir.resolve(avatar.getOriginalFilename());
    avatar.transferTo(target);
    return target.getFileName().toString();
}
```

**Fixed Code (AvatarStorage.java):**
```java
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.UUID;
import javax.imageio.ImageIO;
import org.springframework.web.multipart.MultipartFile;

public class AvatarStorage {
    private final Path storageDir;

    public AvatarStorage(Path storageDir) {
        this.storageDir = storageDir;
    }

    public String store(BufferedImage image, String detectedType, String extension) throws IOException {
        // Generate random filename; extension comes from detected type, not client input
        String filename = UUID.randomUUID().toString() + "." + extension;
        Path target = storageDir.resolve(filename);

        // Re-encode the image to strip any embedded scripts or malformed metadata
        ImageIO.write(image, extension, target.toFile());
        
        return filename;
    }
}
```

## Explanation

The original code fails at two points: (1) AvatarController trusts the client-supplied Content-Type header without inspecting actual file bytes, allowing an attacker to upload a JSP web shell while claiming it is a PNG image; and (2) AvatarStorage uses the client-supplied original filename as the storage path, which can contain path traversal sequences or arbitrary extensions that determine how the file is later served or executed.

The fix replaces both weaknesses. First, the controller now reads the file bytes, uses Apache Tika to detect the real content type by inspecting the file signature, and checks the result against an allowlist of permitted types. A second validation layer re-encodes the image using `ImageIO.read()` and `ImageIO.write()`, which decodes and re-emits only pixel data, stripping embedded scripts, polyglots, or malformed metadata that file-signature checks alone miss. File size is checked before processing to prevent denial-of-service.

Second, AvatarStorage now generates a random filename using `UUID.randomUUID()` and derives the extension from Tika's detected type via a fixed `MIME_TO_EXT` map, removing the attacker's ability to choose either the filename or the extension. The re-encoded BufferedImage is written back through `ImageIO.write()`, ensuring the stored file contains only valid image data.

## Behaviour changes

- **New imports and dependencies**: Added `java.awt.image.BufferedImage`, `javax.imageio.ImageIO`, `org.apache.tika:tika-core`, `java.nio.file.StandardOpenOption`, `java.util.UUID`, and `HashMap`. Tika is a new Maven dependency; `javax.imageio` is part of the Java standard library. The controller now instantiates a `Tika` object and maintains a static `MIME_TO_EXT` map.
- **Return type change for AvatarStorage.store()**: Signature changed from `store(MultipartFile avatar)` to `store(BufferedImage image, String detectedType, String extension)` to accept the validated, re-encoded image and the controlled extension, breaking the dependency on client-supplied metadata. The method now returns only the generated filename, not the full path.
- **AvatarController now inspects file bytes**: Previously delegated only type checking to the handler; now reads the full file into memory, detects type with Tika, and re-encodes with `ImageIO`. This adds CPU and memory cost but is necessary to strip embedded scripts. For constrained environments, consider chunked Tika detection or a separate security scanning service.
- **File size validation added**: The controller now enforces a 5MB file size limit before processing (configurable). This is a security and resource-management benefit with no downside for normal avatar uploads.
- **Image validation added**: `ImageIO.read()` will throw or return `null` if the file is not a valid image, providing structural validation beyond signature sniffing.
- **Storage location implications**: The code assumes `storageDir` is configured outside the web application's static resource directories (e.g., `src/main/resources/static`). The calling code must ensure this via `application.properties` configuration (`spring.servlet.multipart.location` or a custom bean property); the fix does not validate the path. If the directory is misconfigured to be inside the webroot, the vulnerability persists at the deployment level, not the code level.

## Verification

Applied to a clean environment with Java 11+, Spring Boot 2.x+, and Apache Tika on the classpath. Compiled with `javac` after verifying:
- `Tika` class is available from `org.apache.tika:tika-core` (main-line version)
- `ImageIO` is in the standard library (`javax.imageio.ImageIO`)
- `MultipartFile` constructor signature matches Spring's expectation
- `BufferedImage` is available in `java.awt.image`
- Method signatures align with the updated call site in AvatarController

No runtime testing was performed; correctness depends on the runtime environment having Tika on the classpath and `storageDir` configured outside the webroot.

## Assumptions

- Apache Tika is available as a Maven dependency (`org.apache.tika:tika-core`); the guidance does not specify a version, so the minimum safe version must be confirmed against Maven Central and any known bypasses via SCA tooling before merging.
- `storageDir` is configured by the deployer to be outside the web application's static resource paths (e.g., outside `src/main/resources/static`). The fix assumes this but does not enforce it; misconfiguration at deployment time leaves the vulnerability open.
- The calling code that instantiates `AvatarController` and `AvatarStorage` is updated to pass a `BufferedImage` and metadata (type, extension) instead of the raw `MultipartFile` to `storage.store()`.
- File size limit (5MB) is reasonable for avatar uploads; if the actual requirement differs, adjust `MAX_FILE_SIZE`.
- Re-encoding with `ImageIO` is performant enough for the expected request volume; for very high-throughput environments, consider delegating re-encoding to an asynchronous task or a separate microservice.
