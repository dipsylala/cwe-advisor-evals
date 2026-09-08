## Verdict

Confirmed. `AvatarDownloadController.download()` serves a stored file back with `Content-Type: image/svg+xml` and no `Content-Disposition`, so an attacker-uploaded SVG containing `<script>` is executed by the browser when the response is loaded directly (stored XSS). This is CWE-434 (Unrestricted Upload of File with Dangerous Type): SVG is an allowlisted upload type that is nonetheless "dangerous" because it can carry active content, and the application serves it in a way that lets the browser render/execute it.

## Source

`storedName`, the `@PathVariable` on `GET /api/avatars/{storedName}` (`AvatarDownloadController.java:17`) - attacker-controlled at request time, though in the normal flow it is a UUID-based name previously returned by `AvatarStorage.store()`.

## Fix

Assumption: the case's own comment states upload-time validation is already correct - `AvatarStorage.store()` only accepts a `detectedType` "already validated by the caller against an allowlist of image/png, image/jpeg, image/svg+xml, detected from the file's actual bytes" and derives the stored extension from that validated type via `extensionFor()`. That satisfies the CWE-434 upload-side guidance (content-sniffed allowlist, generated filename, extension taken from the detected type, not from client input), so `AvatarStorage.java` is not changed. The finding is squarely on the serve side: SVG is a permitted-but-dangerous type, and the download endpoint returns it in a browser-renderable way. The fix is confined to `AvatarDownloadController.java`.

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

        // Force download instead of inline rendering and block MIME-sniffing so a stored
        // SVG (which the upload path allowlists and can legally carry <script>) can never
        // be executed by a browser that loads this response directly.
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, contentType)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment")
                .header("X-Content-Type-Options", "nosniff")
                .body(bytes);
    }
}
```

## Explanation

The knowledge base's Java CWE-434 guidance states: "When serving a stored file back, set `Content-Type` from the detected type and `Content-Disposition: attachment` for anything a browser would render inline (SVG, HTML)," and to pass `X-Content-Type-Options: nosniff` as a literal header name/value since `HttpHeaders` has no constant for it. The original code set only `Content-Type`, which leaves the response eligible for inline rendering: a browser that navigates to or embeds the URL directly can parse the SVG as a document and execute any `<script>` it contains, turning an accepted upload type into stored XSS. Adding `Content-Disposition: attachment` tells the browser to download the response rather than render it, and `X-Content-Type-Options: nosniff` stops any content-sniffing fallback from reinterpreting the bytes as HTML/SVG even if a client ignores the disposition hint. Both headers are added universally (not conditioned on the `.svg` suffix) so the fix doesn't depend on extension-matching logic remaining correct, and neither changes what bytes are returned or the `Content-Type` value already computed, so legitimate PNG/JPEG avatar downloads behave the same except that they too are now forced to download rather than display inline - see Behaviour changes.

## Behaviour changes

- Every avatar response (PNG, JPEG, and SVG) now includes `Content-Disposition: attachment`, so a browser will download the file instead of rendering it inline. If the frontend currently points an `<img src="/api/avatars/{name}">` tag directly at this endpoint expecting inline display, that will break for all avatar types, not just SVG - inline `<img>` rendering does not execute SVG script content, so a type-specific header (attachment only for `.svg`, inline for raster types) would preserve current `<img>`-based UI while still closing the XSS path if that behaviour is required.
- Added `X-Content-Type-Options: nosniff`, which has no functional effect other than preventing browsers from guessing a different content type than the one returned; this should not affect any legitimate client.
- No change to what bytes are read, how `storedName` is resolved, or the existing `Content-Type` selection logic.

Verification: compiled `AvatarDownloadController.java` with `javac` against real Spring Framework 6.2.19 jars (`spring-web`, `spring-core`, `spring-context`, `spring-beans`) from the local Maven repository - no errors or warnings. `HttpHeaders.CONTENT_DISPOSITION` and `HttpHeaders.CONTENT_TYPE` are verified Spring Framework constants (`org.springframework.http.HttpHeaders`); `X-Content-Type-Options` is passed as a plain string per the loaded guidance since Spring's `HttpHeaders` has no constant for it. `AvatarStorage.java` was read but not modified, since its upload-time allowlist/generated-filename behavior already matches the loaded CWE-434 guidance.
