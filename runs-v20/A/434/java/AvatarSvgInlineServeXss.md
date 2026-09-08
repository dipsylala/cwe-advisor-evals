## Verdict

True positive.

## Source

User-supplied file bytes uploaded as an avatar. `AvatarStorage.store()` accepts `image/svg+xml` as a valid detected content type and writes the bytes to disk unchanged - detection only confirms the declared/sniffed type, not that the markup is inert. `AvatarDownloadController.download()` reads those same bytes back by the stored file name and serves them with `Content-Type: image/svg+xml` and no `X-Content-Type-Options` or `Content-Disposition` control. SVG is XML markup, not a fixed-format bitmap, so a browser navigating to (or embedding) the returned resource will parse and execute any `<script>` element or event-handler attribute the uploaded file contains, in the application's own origin.

## Fix

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
    // image/png, image/jpeg, detected from the file's actual bytes. SVG is intentionally
    // not an allowed avatar type: it is XML markup rather than a fixed-format bitmap, and
    // a stored SVG can carry <script> elements or event-handler attributes that execute
    // wherever the file is later embedded or navigated to directly. Serving SVG avatars
    // safely would require sanitizing/re-encoding the markup before it is written here,
    // which this upload path does not do, so the type is rejected instead.
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

        // AvatarStorage now only ever writes .png/.jpg files. Anything else found on disk
        // (for example a file stored before the upload allowlist was tightened) is served
        // as an inert, forced download rather than as browser-renderable markup, so it
        // cannot execute script even if it carries any.
        String contentType;
        if (storedName.endsWith(".png")) {
            contentType = "image/png";
        } else if (storedName.endsWith(".jpg") || storedName.endsWith(".jpeg")) {
            contentType = "image/jpeg";
        } else {
            contentType = "application/octet-stream";
        }

        ResponseEntity.BodyBuilder response = ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, contentType)
                .header("X-Content-Type-Options", "nosniff");
        if (!contentType.startsWith("image/")) {
            response = response.header(HttpHeaders.CONTENT_DISPOSITION,
                    "attachment; filename=\"" + storedName + "\"");
        }
        return response.body(bytes);
    }
}
```

## Explanation

The durable fix is upstream of the response headers: `AvatarStorage` no longer accepts `image/svg+xml` at all, so no future upload can place active SVG markup into the store in the first place - closing the source rather than only dressing up the sink. PNG and JPEG are fixed raster formats with no script-execution surface, so they continue to be stored and served exactly as before, preserving the existing avatar behavior for the supported types.

`AvatarDownloadController` is hardened as defense-in-depth for anything that might already exist on disk from before this change: it derives the response `Content-Type` from a small explicit allowlist of known-safe extensions rather than trusting the file name to imply a renderable image type, adds `X-Content-Type-Options: nosniff` so browsers cannot MIME-sniff their way around the declared type, and forces a download (`Content-Disposition: attachment`) for anything outside that allowlist. This is deliberately a secondary safeguard, not the primary fix - forcing a download only changes what happens when a browser navigates to the URL directly, and would not prevent an `<img>` tag, API client, or other embedding path from still rendering an SVG's script if one were ever allowed back into storage. Preventing the dangerous type from being written at all is what removes the vulnerability for every consumption path, not just this endpoint.
