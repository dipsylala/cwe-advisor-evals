## Verdict
Confirmed real issue.

## Source
The endpoint serves user-uploaded files based on filename extension without preventing inline script execution. SVG files are served with `Content-Type: image/svg+xml`, which causes browsers to inline and execute any JavaScript within the SVG. An attacker can upload malicious SVG containing executable code, then request it from this endpoint to trigger XSS in the context of the application origin.

## Fix

### File: AvatarDownloadController.java

```java
package cases.upload;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Pattern;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AvatarDownloadController {
    private static final Path STORAGE_ROOT = Path.of("/var/app-data/avatars");
    private static final Pattern SAFE_FILENAME = Pattern.compile("^[a-f0-9\\-]+\\.(png|jpg|svg)$");

    @GetMapping("/api/avatars/{storedName}")
    public ResponseEntity<byte[]> download(@PathVariable String storedName) throws IOException {
        // Validate filename to prevent path traversal and restrict to known extensions
        if (!SAFE_FILENAME.matcher(storedName).matches()) {
            throw new IllegalArgumentException("Invalid filename");
        }

        byte[] bytes = Files.readAllBytes(STORAGE_ROOT.resolve(storedName));
        String contentType = storedName.endsWith(".svg") ? "image/svg+xml" : "image/*";

        // Force download with attachment disposition to prevent inline execution of SVG scripts
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, contentType)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + storedName + "\"")
                .header("X-Content-Type-Options", "nosniff")
                .body(bytes);
    }
}
```

## Explanation
The fix prevents inline script execution in uploaded SVG files through three defensive measures:

1. **Filename Validation**: The storedName parameter is validated against a regex pattern that ensures it matches the UUID+extension format actually used by AvatarStorage. This prevents path traversal attacks and ensures only expected filenames are accepted.

2. **Content-Disposition Header**: Setting `attachment` mode forces the browser to download the file rather than render it inline. This prevents SVG scripts from executing in the application's origin context, eliminating the XSS vector.

3. **X-Content-Type-Options: nosniff**: This header prevents browsers from sniffing the MIME type, ensuring the declared Content-Type is honored and reducing the risk of type confusion attacks.

Together, these changes ensure that even if a malicious SVG is uploaded and stored, it cannot execute JavaScript when served to users.
