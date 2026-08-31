## Verdict

Confirmed. The handler writes an uploaded file to disk using the client-supplied `originalFilename` with no validation of file type, extension, or path content, and the destination directory (`/var/www/html/uploads/`) sits inside the web root. An attacker can upload a file with a server-executable extension (e.g. `.jsp`) and then request it directly to achieve remote code execution, and the unsanitized filename also permits path traversal (`../../`) to write outside the intended directory.

## Source

`e:/Github/cwe-advisor/evals/cases/434/java/MultipartUploadNoValidation/MultipartUploadNoValidation.java`, line 18: `file.getOriginalFilename()` — attacker-controlled input taken from the multipart upload with no downstream validation before being used to build a filesystem path.

## Fix

```java
package evalcases;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Set;
import java.util.UUID;

@RestController
public class MultipartUploadNoValidation {

    // Stored outside the web root so uploaded content can never be served/executed directly.
    private static final Path UPLOAD_DIR = Paths.get("/var/app-data/uploads").toAbsolutePath().normalize();

    private static final Set<String> ALLOWED_EXTENSIONS = Set.of("png", "jpg", "jpeg", "gif", "pdf");

    private static final Set<String> ALLOWED_CONTENT_TYPES = Set.of(
            "image/png", "image/jpeg", "image/gif", "application/pdf");

    private static final long MAX_UPLOAD_BYTES = 10L * 1024 * 1024; // 10 MB

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            throw new IllegalArgumentException("Empty upload");
        }
        if (file.getSize() > MAX_UPLOAD_BYTES) {
            throw new IllegalArgumentException("File too large");
        }

        String contentType = file.getContentType();
        if (contentType == null || !ALLOWED_CONTENT_TYPES.contains(contentType.toLowerCase())) {
            throw new IllegalArgumentException("Unsupported file type");
        }

        String originalFilename = file.getOriginalFilename();
        String extension = extractExtension(originalFilename);
        if (extension.isEmpty() || !ALLOWED_EXTENSIONS.contains(extension)) {
            throw new IllegalArgumentException("Unsupported file extension");
        }

        // Server-generated name: the client-supplied filename never reaches the filesystem,
        // which removes both path traversal and dangerous-extension risk in one step.
        String safeFilename = UUID.randomUUID() + "." + extension;
        Path destination = UPLOAD_DIR.resolve(safeFilename).normalize();

        if (!destination.getParent().equals(UPLOAD_DIR)) {
            throw new IllegalArgumentException("Invalid upload path");
        }

        Files.createDirectories(UPLOAD_DIR);
        try (var in = file.getInputStream()) {
            Files.copy(in, destination, StandardCopyOption.REPLACE_EXISTING);
        }

        return "Uploaded as " + safeFilename;
    }

    private static String extractExtension(String filename) {
        if (filename == null) {
            return "";
        }
        String name = Paths.get(filename).getFileName().toString();
        int dot = name.lastIndexOf('.');
        if (dot < 0 || dot == name.length() - 1) {
            return "";
        }
        return name.substring(dot + 1).toLowerCase();
    }
}
```

## Explanation

The original code took `file.getOriginalFilename()` — a value the client fully controls — and concatenated it directly onto a fixed directory that lives inside the served web root, then wrote the upload there with `transferTo`. That combination lets an attacker (1) supply a filename with an executable extension recognized by the server (e.g. `shell.jsp`) to get a web-executable file dropped where it can later be requested and run, and (2) supply path segments (`../../etc/cron.d/x`) to escape the intended directory entirely, since `File` performs no normalization or containment check.

The fix addresses both the class-of-content and the class-of-path problems, and does so as defense in depth rather than relying on a single check:

- **Type allowlisting, not denylisting**: both the declared `Content-Type` and the file extension are checked against a fixed allowlist of expected, non-executable types. Denylisting extensions is fragile (`.jsp`, `.jspx`, `.jspf`, `.war`, case variants, trailing dots/spaces on some platforms) and new dangerous extensions are easy to miss; an allowlist only needs to be correct for the types the application actually expects.
- **Server-generated filename**: the destination filename is a freshly generated UUID plus the validated extension. The client-supplied name is used only to derive the extension for the allowlist check and is never used to build a filesystem path, which eliminates path traversal and any filename-based tricks (null bytes, alternate data streams, reserved device names) as a side effect — there is no user-controlled string left in the path to sanitize.
- **Path containment check**: even though the filename is server-generated, the code still resolves and normalizes the final path and verifies its parent is exactly `UPLOAD_DIR` before writing, so the logic doesn't silently become unsafe if the generation scheme changes later.
- **Storage outside the web root**: the upload directory is moved out of `/var/www/html`, so even a file that somehow passed validation could not be served and executed by the web server directly; retrieval would go through an application-controlled read endpoint that can apply its own access checks and set a safe `Content-Type`/`Content-Disposition` on the way out.
- **Size limit**: bounds the upload to prevent trivial denial-of-service via oversized files, independent of the type/path fixes.

If the application genuinely needs to preserve the original filename for display, store it separately (e.g. in a database column alongside the generated storage name) rather than using it in the filesystem path.
