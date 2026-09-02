## Verdict

Exploitable. Line 20 of AvatarController validates file type using `avatar.getContentType()`, which is a client-supplied HTTP header that can be forged. An attacker can send a JSP web shell with `Content-Type: image/png` to pass validation, then AvatarStorage stores it under the client-supplied filename (line 15), allowing execution if the storage directory is served by the application.

## Source

HTTP request parameter `avatar` (MultipartFile) in the POST `/profile/avatar` handler, which carries the client-controlled filename and Content-Type header.

## Fix

**AvatarController.java:**

```java
package cases.upload;

import java.io.IOException;
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
    private static final Tika tika = new Tika();

    public AvatarController(AvatarStorage storage) {
        this.storage = storage;
    }

    @PostMapping("/profile/avatar")
    public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
        // Detect actual file content by inspecting bytes, not trusting client-supplied Content-Type
        String detectedType = tika.detect(avatar.getInputStream());
        
        if (!"image/png".equals(detectedType) && !"image/jpeg".equals(detectedType)) {
            return ResponseEntity.badRequest().body("unsupported avatar");
        }

        return ResponseEntity.ok(storage.store(avatar, detectedType));
    }
}
```

**AvatarStorage.java:**

```java
package cases.upload;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.UUID;
import javax.imageio.ImageIO;
import org.springframework.web.multipart.MultipartFile;

public class AvatarStorage {
    private final Path storageDir;
    private static final java.util.Map<String, String> mimeToExt = java.util.Map.of(
        "image/png", ".png",
        "image/jpeg", ".jpg"
    );

    public AvatarStorage(Path storageDir) {
        this.storageDir = storageDir;
    }

    public String store(MultipartFile avatar, String detectedType) throws IOException {
        // Generate random filename; derive extension from detected type (not client-supplied filename)
        String extension = mimeToExt.getOrDefault(detectedType, "");
        String randomName = UUID.randomUUID().toString() + extension;
        Path target = storageDir.resolve(randomName);

        // For images, re-encode to strip embedded scripts and malformed metadata
        if (detectedType.startsWith("image/")) {
            var image = ImageIO.read(avatar.getInputStream());
            ImageIO.write(image, detectedType.substring(6), target.toFile());
        } else {
            avatar.transferTo(target);
        }
        
        return randomName;
    }
}
```

**application.properties:**

```properties
spring.servlet.multipart.max-file-size=5MB
spring.servlet.multipart.max-request-size=5MB
```

**pom.xml** (add Tika dependency):

```xml
<dependency>
    <groupId>org.apache.tika</groupId>
    <artifactId>tika-core</artifactId>
    <version>2.9.1</version>
</dependency>
```

## Explanation

The vulnerability arises from trusting `avatar.getContentType()` on line 20, which is a direct reflection of the client-supplied HTTP `Content-Type` header. An attacker can forge this header to bypass the validation (e.g., claim `image/png` while uploading a JSP). The file then gets stored under the client-supplied filename via `avatar.getOriginalFilename()` in AvatarStorage, enabling execution. The fix replaces this unsafe pattern with Apache Tika's byte-content sniffing to detect the actual file type regardless of client claims, validates against an allowlist of detected types, generates a random UUID-based filename to break any taint from the original filename, derives the extension from the detected type through a fixed map rather than the original filename, and re-encodes images through `ImageIO` to strip embedded scripts or malformed metadata that raw bytes may carry. File size limits are enforced via Spring Boot configuration, and the storage directory should be outside the webroot or served only through application-controlled endpoints that force download rather than execution.

## Behaviour changes

- **Added Tika dependency**: `org.apache.tika:tika-core:2.9.1` is now required to perform content-sniffing detection; this adds a runtime dependency but eliminates reliance on client-supplied headers.
- **Random filename generation**: Storage filename is now a UUID rather than the client-supplied original filename; this prevents path traversal and lets the application control how files are served, but invalidates any expectations that the filename persists across requests.
- **Extension derived from detected type**: The file extension is now determined by the detected MIME type through a fixed `mimeToExt` map, not from the original filename; this ensures consistency between how the file is detected and how it is later served, but means the stored extension may differ from the original.
- **Image re-encoding**: Image files are now decoded and re-encoded through `ImageIO`, which strips embedded scripts and metadata but adds CPU overhead and converts images to a standard format (original metadata and EXIF data is discarded).
- **Method signature change**: `AvatarStorage.store()` now takes the detected type as a parameter; callers must provide this, but the method no longer accepts untrusted input from `MultipartFile.getOriginalFilename()`.
- **Configuration hardening**: `spring.servlet.multipart.max-file-size` and `spring.servlet.multipart.max-request-size` should be set in `application.properties` to a size appropriate for avatars; defaults are conservative (1MB/10MB) and should be reviewed against actual use.
