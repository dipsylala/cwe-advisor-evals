## Verdict

exploitable

## Source

Uploaded SVG file with embedded `<script>` tags, validated by caller and stored via `AvatarStorage.store(bytes, "image/svg+xml")`, retrieved from storage path via `storedName` path parameter in `AvatarDownloadController.download()`.

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
        String contentType = storedName.endsWith(".svg") ? "image/svg+xml" : "image/*";

        // Prevent XSS: force SVG files to be downloaded as attachments, not rendered inline
        // Add security headers to mitigate MIME type confusion
        ResponseEntity.ResponseEntityBuilder builder = ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_TYPE, contentType)
            .header("X-Content-Type-Options", "nosniff");

        if (storedName.endsWith(".svg")) {
            builder.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + storedName + "\"");
        }

        return builder.body(bytes);
    }
}
```

## Explanation

SVG files are a dangerous upload type because they can contain inline JavaScript (`<script>` tags) that executes when the file is rendered by a browser. The original code served SVG files with `Content-Type: image/svg+xml`, causing the browser to interpret and execute embedded scripts as Stored XSS.

The fix adds two security layers to the download endpoint:

1. **Forced attachment download for SVG**: The `Content-Disposition: attachment` header instructs the browser to download SVG files rather than render them inline. This prevents embedded scripts from being executed in the page context.

2. **MIME type sniffing prevention**: The `X-Content-Type-Options: nosniff` header prevents browsers from sniffing the actual file type and overriding the declared `Content-Type`, adding defense-in-depth against MIME confusion attacks.

These headers transform the response from one that triggers browser rendering and script execution into one that forces a download, breaking the XSS attack chain. The fix preserves the existing API contract: the response still contains the file bytes and declares the correct content type for legitimate clients that need it.

## Behaviour changes

- **New response header `X-Content-Type-Options: nosniff`**: Added to all responses. This is a safety hardening header that instructs browsers not to sniff MIME types; it does not alter core application behavior but strengthens defense against MIME confusion attacks.
- **Conditional `Content-Disposition: attachment` for SVG files**: For filenames ending in `.svg`, adds `Content-Disposition: attachment; filename="<storedName>"`. This changes how the browser handles SVG responses from inline rendering (where scripts execute) to download prompts (where files are saved to disk), which is the security fix. Non-SVG responses are unaffected.
- **Response builder instead of one-liner**: The response is now constructed with `ResponseEntity.ResponseEntityBuilder` to conditionally add headers. The underlying response body and content type remain identical; this is a refactoring of how the response is built, not a change to the HTTP contract.
