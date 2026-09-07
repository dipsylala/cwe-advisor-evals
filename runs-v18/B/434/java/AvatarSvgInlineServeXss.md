## Verdict

Exploitable. SVG files served with `Content-Type: image/svg+xml` header are parsed and rendered by the browser, allowing embedded JavaScript to execute as an XSS payload.

## Source

The `storedName` path parameter originates from the HTTP request (`@PathVariable String storedName` in the `@GetMapping("/api/avatars/{storedName}")` handler). The value is expected to be a generated filename (UUID + extension) from the `AvatarStorage.store()` method, validated by the caller to correspond to an allowlisted image type.

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
        
        var builder = ResponseEntity.ok();
        
        // Determine content type and apply safe serving headers based on detected file extension
        if (storedName.endsWith(".svg")) {
            // SVG files can contain embedded scripts - serve as attachment to prevent inline rendering and XSS
            builder.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"avatar.svg\"");
            builder.header(HttpHeaders.CONTENT_TYPE, "image/svg+xml");
        } else if (storedName.endsWith(".png")) {
            builder.header(HttpHeaders.CONTENT_TYPE, "image/png");
        } else if (storedName.endsWith(".jpg")) {
            builder.header(HttpHeaders.CONTENT_TYPE, "image/jpeg");
        } else {
            // Default to octet-stream for unknown types to prevent browser sniffing
            builder.header(HttpHeaders.CONTENT_TYPE, "application/octet-stream");
        }
        
        // Prevent MIME-type sniffing
        builder.header(HttpHeaders.X_CONTENT_TYPE_OPTIONS, "nosniff");
        
        return builder.body(bytes);
    }
}
```

## Explanation

The vulnerability occurs because SVG files served with `Content-Type: image/svg+xml` are parsed and rendered by browsers, which execute any embedded `<script>` elements. The fix adds three layers of defence: (1) SVG files are served with `Content-Disposition: attachment`, forcing the browser to download the file instead of rendering it inline, preventing embedded script execution; (2) the content type mapping is made explicit for known formats (PNG, JPEG) and defaults to `application/octet-stream` for unknowns instead of the generic and invalid `image/*`; and (3) the `X-Content-Type-Options: nosniff` header prevents browsers from attempting to sniff the content type, ensuring the server-supplied type is respected. This aligns with CWE-434 guidance that advises serving uploaded files through application-controlled logic with safe response headers (forced attachment download, no-sniff).

## Behaviour changes

The fix introduces the following behaviour changes to the original code:

1. **SVG attachment download**: SVG files are now served with `Content-Disposition: attachment`, which causes browsers to download the file instead of rendering it inline. This changes user-facing behaviour - avatar images served as SVG will trigger a download dialog rather than display inline. This trade-off is intentional: preventing XSS execution takes precedence over inline display.

2. **Content-Type specificity**: The original code used the generic `image/*` for non-SVG files, which is not a valid MIME type. The fix maps known extensions (`.png` → `image/png`, `.jpg` → `image/jpeg`) and defaults unknown types to `application/octet-stream`. This ensures accurate content type negotiation and prevents browser sniffing.

3. **X-Content-Type-Options header**: The `nosniff` header is now included in all responses, instructing browsers not to perform MIME-type sniffing. This hardens the response against browser-level content-type confusion attacks.

The ResponseEntity API contract remains intact: the method still returns `ResponseEntity<byte[]>` with a 200 OK status and the file bytes as the body.

