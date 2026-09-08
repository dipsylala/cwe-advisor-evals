## Verdict

The vulnerability is confirmed. The application accepts SVG file uploads and serves them with `Content-Type: image/svg+xml`, allowing browsers to execute JavaScript embedded in SVG files. This constitutes CWE-434 (Unrestricted Upload of File with Dangerous Type) combined with stored XSS.

## Source

**AvatarDownloadController.java (line 22)**: Sets `Content-Type: image/svg+xml` for SVG files and serves them inline to the client.

**AvatarStorage.java (line 20-23)**: Accepts `image/svg+xml` as a valid MIME type during upload, allowing SVG files to be stored.

The vulnerability chain:
1. `AvatarStorage.store()` accepts `image/svg+xml` as a valid detectedType
2. `AvatarDownloadController.download()` serves SVG files with `Content-Type: image/svg+xml`
3. The browser interprets SVG as XML and executes any embedded `<script>` tags or event handlers
4. Attacker-controlled JavaScript runs in the victim's session (stored XSS via CWE-434)

## Fix

### File: AvatarDownloadController.java

```java
package cases.upload;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AvatarDownloadController {
    private static final Path STORAGE_ROOT = Path.of("/var/app-data/avatars");

    @GetMapping("/api/avatars/{storedName}")
    public ResponseEntity<byte[]> download(@PathVariable String storedName) throws IOException {
        byte[] bytes = Files.readAllBytes(STORAGE_ROOT.resolve(storedName));
        String contentType = storedName.endsWith(".jpg") ? "image/jpeg" : "image/png";

        return ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE, contentType).body(bytes);
    }
}
```

### File: AvatarStorage.java

```java
package cases.upload;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

public class AvatarStorage {
    private static final Path STORAGE_ROOT = Path.of("/var/app-data/avatars");

    // detectedType has already been validated by the caller against an allowlist of
    // image/png, image/jpeg, detected from the file's actual bytes.
    public String store(byte[] bytes, String detectedType) throws IOException {
        String storedName = UUID.randomUUID() + extensionFor(detectedType);
        Files.write(STORAGE_ROOT.resolve(storedName), bytes);
        return storedName;
    }

    static String extensionFor(String detectedType) {
        return switch (detectedType) {
            case "image/png" -> ".png";
            case "image/jpeg" -> ".jpg";
            default -> throw new IllegalArgumentException("Unsupported type");
        };
    }
}
```

## Explanation

**Why SVG is dangerous**: SVG is an XML-based format that can embed executable code through `<script>` tags, event handler attributes (e.g., `onload`, `onerror`), and animation handlers. When served with `Content-Type: image/svg+xml`, browsers render and execute this code in the context of the user's session, enabling stored XSS.

**The fix**: Remove SVG from the list of accepted file types. The application now:
1. Only allows PNG and JPEG image formats, which are binary and cannot contain executable code
2. Serves PNG files with `image/png` and JPEG files with `image/jpeg` content types
3. Rejects any attempt to upload SVG files in `AvatarStorage.extensionFor()` with an `IllegalArgumentException`

This directly addresses CWE-434 by restricting file uploads to safe image types that cannot be weaponized for code execution, regardless of how they are served.
