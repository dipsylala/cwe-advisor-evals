## Verdict

exploitable

- cwe_id: CWE-434
- location: `MultipartUploadNoValidation.java`, line 21 (`file.transferTo(destination)`)
- confidence: high

## Source

`MultipartFile file` bound from the `@RequestParam("file")` on the `/upload` `@PostMapping` handler (line 17). The attacker fully controls the multipart body, and `file.getOriginalFilename()` (line 18) returns the client-supplied filename verbatim with no server-side check on content, extension, or path.

## Fix

### File: MultipartUploadNoValidation.java

```java
package evalcases;

import org.apache.tika.Tika;
import org.apache.tika.mime.MimeType;
import org.apache.tika.mime.MimeTypeException;
import org.apache.tika.mime.MimeTypes;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Set;
import java.util.UUID;

@RestController
public class MultipartUploadNoValidation {

    // Storage directory outside any path the web server or Spring serves directly.
    private static final Path UPLOAD_DIR = Paths.get("/var/app-data/uploads/");

    private static final Set<String> ALLOWED_CONTENT_TYPES = Set.of(
            "image/png", "image/jpeg", "application/pdf");

    private static final Tika TIKA = new Tika();

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        byte[] content = file.getBytes();

        String detectedType = TIKA.detect(content);
        if (!ALLOWED_CONTENT_TYPES.contains(detectedType)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported file type");
        }

        String extension;
        try {
            MimeType mimeType = MimeTypes.getDefaultMimeTypes().forName(detectedType);
            extension = mimeType.getExtension();
        } catch (MimeTypeException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported file type");
        }
        if (extension == null || extension.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported file type");
        }

        String storedFilename = UUID.randomUUID() + extension;
        Path destination = UPLOAD_DIR.resolve(storedFilename);

        try (InputStream in = file.getInputStream();
             OutputStream out = Files.newOutputStream(destination, StandardOpenOption.CREATE_NEW)) {
            in.transferTo(out);
        }

        return "Uploaded as " + storedFilename;
    }
}
```

**Library recommendation:** Apache Tika (`org.apache.tika:tika-core`), used via `new Tika().detect(byte[])` and `MimeTypes.getDefaultMimeTypes().forName(type)`, per the loaded Java guidance. The guidance carries no minimum safe version for this artifact; resolve the version through SCA/dependency-check tooling before merging rather than pinning one from recall.

## Explanation

The original handler wrote the upload to `UPLOAD_DIR + originalFilename` - a path built directly from the client-supplied filename, with no check on the file's actual type, inside `/var/www/html/uploads/`, a path under the webroot. An attacker could upload a JSP/PHP web shell (or any executable) named to land inside a servable directory, or use `../` sequences in the filename to write outside the intended folder, and the server would serve or execute it later.

The fix reads the file content once (`file.getBytes()`) and detects its real type from the bytes with Tika (`tika.detect(content)`), rejecting anything not on the `ALLOWED_CONTENT_TYPES` allowlist before any write occurs. The stored filename is generated (`UUID.randomUUID()`), never derived from `getOriginalFilename()`, eliminating traversal through the filename entirely. The stored extension is taken from the Tika-detected type via `MimeTypes.getDefaultMimeTypes().forName(detectedType).getExtension()` - the allowlist-matched value, not the client's original suffix - so the attacker cannot control the extension that later determines how the file is served, closing the taint-break the guidance requires. Both the checked `MimeTypeException` and an empty extension result (a real type Tika can identify but that has no associated extension) are treated as rejection rather than allowed to reach the filesystem with a malformed name. The write target `/var/app-data/uploads/` is outside the webroot, unlike the original `/var/www/html/uploads/`, so even a file that passed validation would not be directly served or executed by the web server. The write uses `Files.newOutputStream(destination, StandardOpenOption.CREATE_NEW)` copying from `file.getInputStream()`, so a filename collision fails loudly (`FileAlreadyExistsException`) instead of silently overwriting another stored file.

Two items from the guidance are out of scope for this single file: image re-encoding (`javax.imageio.ImageIO`) to strip embedded active content from image uploads, and setting `spring.servlet.multipart.max-file-size`/`max-request-size`, which lives in `application.properties`, not in this controller. Both are recommended as follow-up hardening.

## Behaviour changes

- **Response body changed**: original returned `"Uploaded to " + destination.getAbsolutePath()`, exposing the server's absolute filesystem path to the client. Fixed code returns `"Uploaded as " + storedFilename` (just the generated name). Reason: returning the server's internal absolute path is an information leak that a stricter storage/serving redesign should not reintroduce; the endpoint's functional contract (confirm success, name the stored artifact) is preserved.
- **Storage location changed**: from `/var/www/html/uploads/` (webroot) to `/var/app-data/uploads/` (outside webroot). Reason: required by the CWE-434 guidance - files inside the webroot are directly servable/executable by the web server regardless of content validation.
- **Storage filename changed**: from the client-supplied original filename to a generated `UUID + allowlist-derived-extension`. Reason: required by the guidance to remove path traversal and attacker control over the extension that determines how the file is later served.
- **New rejection path**: requests whose content does not match the allowlist, or whose detected type has no known extension, now receive HTTP 400 (`ResponseStatusException`) instead of being written to disk. Reason: this is the allowlist gate itself - the vulnerability was the complete absence of one.
- **Overwrite behaviour changed**: `StandardOpenOption.CREATE_NEW` fails on a name collision instead of silently overwriting, per the guidance's explicit instruction to write with `CREATE_NEW`. With a random UUID-based name, collisions are not expected in normal operation.
- Not preserved: request size limiting (`spring.servlet.multipart.max-file-size`/`max-request-size`) and image re-encoding are guidance-recommended defense-in-depth that this single-file fix cannot add, since they require a properties file and additional processing not present in the original chain.

## Verification

Compiled with `javac` (JDK 26) against hand-written stub classes reproducing the exact signatures the loaded guidance names (`org.apache.tika.Tika.detect(byte[])`, `org.apache.tika.mime.MimeTypes.getDefaultMimeTypes().forName(String)` throwing `MimeTypeException`, `MimeType.getExtension()`, plus `MultipartFile`, `PostMapping`, `RequestParam`, `RestController`, `ResponseStatusException`, `HttpStatus`) - the real Spring/Tika jars were not reachable in this environment. Compilation succeeded with zero errors and zero warnings, confirming every import resolves, every method call's argument list and return type matches the API shape the guidance describes, and the file is otherwise syntactically valid. This does not substitute for compiling against the real `tika-core`/`spring-web` jars, which should be done before merging.

## Assumptions

- No `application.properties` (or equivalent Spring configuration) was present in the case's call chain, so `spring.servlet.multipart.max-file-size`/`max-request-size` could not be set as part of this fix; noted as a follow-up.
- The allowlist (`image/png`, `image/jpeg`, `application/pdf`) is illustrative - the actual set of business-required MIME types was not specified by the finding and should be set by whoever owns the endpoint's requirements.
- Verification ran against hand-written stubs, not the real `tika-core`/`spring-web`/`spring-webmvc` artifacts, since no dependency jars were reachable in this environment; confidence in the fix's structural correctness is high, but a build against the real dependencies is still recommended before merge.
