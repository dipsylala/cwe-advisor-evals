## Verdict

Confirmed. `handleUpload` writes an uploaded `MultipartFile` to disk using the client-supplied `originalFilename` with no restriction on file type, and the destination directory (`/var/www/html/uploads/`) is inside the web root, so an attacker can upload a `.jsp`/`.jspx` (or other server-executable) file and then request it directly to achieve remote code execution. The filename is also used unsanitized, which additionally permits path traversal (`../../`) to write outside the intended directory.

## Source

`MultipartFile file` obtained from the `@RequestParam("file")` on the `/upload` endpoint (`handleUpload`, line 17) — attacker-controlled via `file.getOriginalFilename()` (line 18) and the file's binary content, both submitted directly in the HTTP multipart request.

## Fix

```java
package evalcases;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;
import java.util.UUID;

@RestController
public class MultipartUploadNoValidation {

    // Stored outside the web root / any servlet-mapped, executable path.
    private static final Path UPLOAD_DIR = Paths.get("/var/app-data/uploads").toAbsolutePath().normalize();

    // Allowlist of permitted extensions - reject everything else, including
    // double extensions and any executable/script type (.jsp, .jspx, .php, .asp, .exe, ...).
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of("png", "jpg", "jpeg", "gif", "pdf");

    private static final Set<String> ALLOWED_CONTENT_TYPES = Set.of(
            "image/png", "image/jpeg", "image/gif", "application/pdf");

    private static final long MAX_FILE_SIZE = 5L * 1024 * 1024; // 5 MB

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        if (file.isEmpty() || file.getSize() > MAX_FILE_SIZE) {
            throw new IllegalArgumentException("Invalid file size");
        }

        String contentType = file.getContentType();
        if (contentType == null || !ALLOWED_CONTENT_TYPES.contains(contentType.toLowerCase())) {
            throw new IllegalArgumentException("Unsupported content type");
        }

        String originalFilename = file.getOriginalFilename();
        if (originalFilename == null || originalFilename.isBlank()) {
            throw new IllegalArgumentException("Missing filename");
        }

        String extension = extractExtension(originalFilename);
        if (!ALLOWED_EXTENSIONS.contains(extension)) {
            throw new IllegalArgumentException("Unsupported file type");
        }

        // Ignore the client-supplied name entirely for the on-disk filename;
        // this closes the path-traversal vector as well.
        String storedFilename = UUID.randomUUID() + "." + extension;

        Files.createDirectories(UPLOAD_DIR);
        Path destination = UPLOAD_DIR.resolve(storedFilename).normalize();
        if (!destination.startsWith(UPLOAD_DIR)) {
            throw new IllegalArgumentException("Invalid destination path");
        }

        file.transferTo(destination.toFile());
        return "Uploaded as " + storedFilename;
    }

    private static String extractExtension(String filename) {
        int dot = filename.lastIndexOf('.');
        if (dot < 0 || dot == filename.length() - 1) {
            return "";
        }
        return filename.substring(dot + 1).toLowerCase();
    }
}
```

## Explanation

The original code trusted the client on every axis of this finding: it took the attacker-supplied `originalFilename` verbatim as the destination path, applied no allowlist or denylist on file type, and wrote into `/var/www/html/uploads/`, a directory served directly by the web server. Any uploaded `.jsp` (or `.jspx`, `.jspf`, etc., depending on the servlet container's mapping) becomes directly requestable and executes with the application's privileges — a direct path to remote code execution — and the unsanitized filename also permits `../` traversal to place files elsewhere on disk.

The fix addresses each part of the chain:

- **Type restriction (the CWE-434 core fix):** an explicit allowlist of extensions (`ALLOWED_EXTENSIONS`) and declared MIME types (`ALLOWED_CONTENT_TYPES`) rejects anything not on the list, rather than trying to block known-dangerous types. Content-Type is client-supplied and not authoritative on its own, but combined with the extension allowlist it removes the trivial bypass of just renaming a script's extension while claiming an image content type is still blocked by the extension check, and vice versa. (For stronger assurance, verify magic bytes/signature against the declared type using a content-detection library before persisting.)
- **Filename handling:** the on-disk filename is generated server-side (`UUID.randomUUID()`) instead of reusing client input, which eliminates path traversal and filename-collision/overwrite risks in one step; the original name is never used for the file system path.
- **Storage location:** the upload directory is moved outside the web root (`/var/app-data/uploads` rather than `/var/www/html/uploads/`), so even a file that passed validation cannot be directly requested and executed by the web server — files should be served, if needed, through a controller endpoint that reads and streams them rather than by direct static-file mapping.
- **Path confinement:** resolving the destination against the upload directory and checking `startsWith` defends in depth against any path-escaping edge case in the generated name.
- **Size limit:** bounds resource consumption from oversized uploads.

To verify: attempt to upload a file with a `.jsp`/`.php` extension (rejected by the extension check), a file with an allowed extension but a mismatched `Content-Type` (rejected), a filename containing `../` sequences (neutralized because the stored name is server-generated), and a valid image/PDF under the size limit (accepted and stored under a generated name outside the web root).
