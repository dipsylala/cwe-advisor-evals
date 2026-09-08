## Verdict

**Real vulnerability - XSS via unsafe SVG serving**

The `AvatarDownloadController` serves SVG files with `Content-Type: image/svg+xml` but without `Content-Disposition: attachment`. Browsers render SVG inline when served with this content type, allowing embedded JavaScript (e.g., `<svg onload="alert('XSS')">`) to execute in the application's domain, bypassing XSS protections.

## Source

**Vulnerable endpoint:**
- `AvatarDownloadController.download()` at line 22
- File: `AvatarDownloadController.java`

**Data flow:**
1. Request enters via `@GetMapping("/api/avatars/{storedName}")` with storedName path parameter
2. File bytes are read from `/var/app-data/avatars/{storedName}` via `Files.readAllBytes()`
3. Content-Type header is set based on the filename extension (line 19: if `.svg`, then `image/svg+xml`)
4. Response is returned with bytes and headers, but missing `Content-Disposition: attachment` (line 22)
5. Browser receives `image/svg+xml` content type without attachment disposition and renders SVG inline

**The missing control:**
Inline-renderable content types (SVG, HTML) require `Content-Disposition: attachment` to prevent browser execution of embedded scripts. SVG files with malicious payloads (event handlers, script tags, etc.) will execute when served inline.

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

        ResponseEntity.BodyBuilder response = ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE, contentType);
        if (storedName.endsWith(".svg")) {
            response = response.header("Content-Disposition", "attachment");
        }
        return response.body(bytes);
    }
}
```

## Explanation

The fix adds a `Content-Disposition: attachment` header when serving SVG files. This forces the browser to download the file instead of rendering it inline, preventing JavaScript execution.

**What changed:**
1. Extracted `ResponseEntity.ok()` to a `BodyBuilder` variable to allow conditional header chaining
2. Added a check: if storedName ends with `.svg`, chain an additional `.header("Content-Disposition", "attachment")` call
3. The header forces download behavior, preventing inline SVG script execution

**Why this closes the weakness:**
- SVG files can contain active content (event handlers like `onload`, `onclick`, or embedded `<script>` tags)
- `Content-Type: image/svg+xml` alone tells the browser to render the SVG, executing any scripts
- `Content-Disposition: attachment` overrides this behavior and forces download, treating the content as an attachment rather than inline content
- The combination prevents XSS while maintaining correct content type metadata

This uses only Spring Framework's standard `ResponseEntity.BodyBuilder` API (`.header()` method), which is already imported and used in the original code. No new dependencies are introduced.

## Behaviour changes

**Response headers for SVG files change from:**
```
Content-Type: image/svg+xml
```

**To:**
```
Content-Type: image/svg+xml
Content-Disposition: attachment
```

**User-facing impact:**
- SVG avatars will now download to the user's device instead of rendering inline
- This is intentional and correct: downloaded files cannot execute in the web application's security context
- Other image types (PNG, JPEG via `image/*` content type) are unaffected and continue to render inline as before

**Application contract:**
- Return value: still `ResponseEntity<byte[]>` with the same file bytes
- File storage: unchanged (files still stored at `/var/app-data/avatars` with random UUID names and appropriate extensions)
- HTTP semantics: file is still readable via the same GET endpoint, but with secure download semantics instead of inline rendering
