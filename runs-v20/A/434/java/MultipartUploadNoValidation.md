## Verdict

Confirmed. `handleUpload` builds the destination path by concatenating a fixed upload directory with the client-supplied `originalFilename` and passes it straight to `MultipartFile.transferTo()` with no check on the file's type/extension and no containment check on the resulting path. An attacker can upload a file with an executable extension (e.g. a `.jsp`/`.war` dropped under a web-served directory) and, because the filename is untrusted, can also embed `../` sequences to write outside `UPLOAD_DIR` (path traversal combined with unrestricted type).

## Source

`file.getOriginalFilename()` at line 18 (`MultipartFile` parameter bound from the `multipart/form-data` request body via `@RequestParam("file")`) is the tainted input. It flows unmodified into the `File` path built at line 19 and into the write sink `file.transferTo(destination)` at line 21.

## Fix

### File: MultipartUploadNoValidation.java
```java
package evalcases;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

@RestController
public class MultipartUploadNoValidation {

    private static final Path UPLOAD_DIR = Paths.get("/var/www/html/uploads/").toAbsolutePath().normalize();

    // Allowlist of extensions this endpoint is intended to accept. Adjust to the
    // application's actual business need; do not widen this to cover every type
    // a user might send.
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of("png", "jpg", "jpeg", "gif", "pdf");

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Empty file");
        }

        String originalFilename = file.getOriginalFilename();
        String extension = extractExtension(originalFilename);
        if (extension == null || !ALLOWED_EXTENSIONS.contains(extension)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "File type not permitted");
        }

        // Never write the client-supplied name to disk: generate a new one so the
        // upload cannot contain path separators, "..", or a dangerous double
        // extension (e.g. "report.pdf.jsp").
        String storedFilename = UUID.randomUUID() + "." + extension;
        Path destination = UPLOAD_DIR.resolve(storedFilename).normalize();

        // Defense in depth: confirm the resolved path is still inside UPLOAD_DIR
        // before writing, in case UPLOAD_DIR or the resolution logic changes later.
        if (!destination.getParent().equals(UPLOAD_DIR)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid upload path");
        }

        Files.createDirectories(UPLOAD_DIR);
        file.transferTo(destination);
        return "Uploaded to " + destination;
    }

    private static String extractExtension(String filename) {
        if (filename == null) {
            return null;
        }
        // Only the final path segment matters; a client can still send path
        // separators inside "filename" even though we never reuse the name itself.
        String name = filename.replace('\\', '/');
        int lastSlash = name.lastIndexOf('/');
        if (lastSlash >= 0) {
            name = name.substring(lastSlash + 1);
        }
        int dot = name.lastIndexOf('.');
        if (dot < 0 || dot == name.length() - 1) {
            return null;
        }
        return name.substring(dot + 1).toLowerCase(Locale.ROOT);
    }
}
```

## Explanation

The rewrite closes both the "dangerous type" and the path-traversal angle the original code left open:

- **Type restriction**: the file's extension is checked against an explicit allowlist (`ALLOWED_EXTENSIONS`) before anything is written. Only extensions the application actually needs to accept are permitted; everything else is rejected with `400 Bad Request`. This is a product decision the entry's author should tune to the real set of file types the endpoint needs to serve - it is not meant to be widened "just in case".
- **No untrusted filename ever reaches the filesystem**: instead of sanitizing `originalFilename` (stripping is fragile - see the CRLF/space rewrite failure mode for mail headers, the same principle applies here to filenames), the code discards it entirely and generates a fresh `UUID`-based name, keeping only the already-validated extension. This eliminates path traversal (`../../etc/cron.d/x`), null-byte tricks, and double-extension smuggling (`shell.jsp.png`) in one step, because the attacker-controlled string never becomes part of the path.
- **Defense in depth**: even though the generated name cannot contain separators, the code still resolves the destination against the fixed `UPLOAD_DIR`, normalizes it, and asserts the parent directory is exactly `UPLOAD_DIR` before calling `transferTo()`. This guards against a future change (e.g. someone reintroducing part of the original filename into `storedFilename`) silently reopening the traversal.
- **Verification**: a test that uploads a file named `../../evil.jsp` (or any name outside the allowlist) must be rejected with `400` and must not create any file outside `UPLOAD_DIR`; a test that uploads a legitimately-named `.png`/`.pdf` file must succeed and land inside `UPLOAD_DIR` under a generated name. Testing only with a `.jsp` extension is not sufficient - a passing case must also confirm traversal sequences in the filename are neutralized, since fixing type restriction alone would not have caught that.
