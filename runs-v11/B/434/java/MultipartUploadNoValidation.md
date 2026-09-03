## Verdict

Exploitable. The finding correctly identifies CWE-434: the uploaded file is accepted without validating its actual content type, and the original client-supplied filename is used directly as the storage path, allowing both path traversal and execution of malicious file types within the webroot.

## Source

- **Source**: `MultipartFile file` parameter (line 17), attacker-controlled via HTTP multipart request
- **Taint propagation**: `file.getOriginalFilename()` (line 18) returns the client-supplied filename header without validation
- **Sink**: `file.transferTo(destination)` (line 21) writes the file bytes to a path constructed from the untrusted filename

## Fix

**Vulnerable code:**
```java
@PostMapping("/upload")
public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
    String originalFilename = file.getOriginalFilename();
    File destination = new File(UPLOAD_DIR + originalFilename);
    // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
    file.transferTo(destination);
    return "Uploaded to " + destination.getAbsolutePath();
}
```

**Fixed code:**
```java
import org.apache.tika.Tika;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

private static final String UPLOAD_DIR = "/var/uploads/";
private static final Set<String> ALLOWED_TYPES = new HashSet<>();
private static final Tika TIKA = new Tika();
private static final java.util.Map<String, String> EXTENSION_MAP = 
    java.util.Map.of(
        "image/jpeg", ".jpg",
        "image/png", ".png",
        "application/pdf", ".pdf"
    );

static {
    ALLOWED_TYPES.add("image/jpeg");
    ALLOWED_TYPES.add("image/png");
    ALLOWED_TYPES.add("application/pdf");
}

@PostMapping("/upload")
public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
    if (file.isEmpty()) {
        throw new IllegalArgumentException("File is empty");
    }

    // Detect actual file type from content bytes
    byte[] fileBytes = file.getBytes();
    String detectedType = TIKA.detect(fileBytes);

    // Validate against allowlist
    if (!ALLOWED_TYPES.contains(detectedType)) {
        throw new IllegalArgumentException("File type not allowed: " + detectedType);
    }

    // Enforce file size limit
    if (file.getSize() > 5 * 1024 * 1024) {
        throw new IllegalArgumentException("File too large");
    }

    // Generate random filename; derive extension from detected type
    String randomFilename = UUID.randomUUID().toString() + EXTENSION_MAP.get(detectedType);
    Path uploadPath = Paths.get(UPLOAD_DIR, randomFilename);

    // Write with CREATE_NEW to prevent overwrite attacks
    Files.write(uploadPath, fileBytes, StandardOpenOption.CREATE_NEW);

    return "Uploaded to " + uploadPath.toAbsolutePath();
}
```

**Library recommendation:**
Add Apache Tika as a dependency: `org.apache.tika:tika-core`. No specific version is mandated by the guidance; consult your project's SCA tool to confirm the latest release is free of known vulnerabilities.

## Explanation

The fix closes CWE-434 by applying all four primary defences from the guidance. First, it reads the actual file bytes and uses Tika (`tika.detect(bytes)`) to sniff the real MIME type, not trusting the client-supplied `Content-Type` header or filename extension. Second, it validates the detected type against a server-controlled allowlist, rejecting anything not explicitly permitted. Third, it generates a random filename using `UUID.randomUUID()`, eliminating the path-traversal risk and preventing the client from controlling the storage path. Fourth, it derives the file extension from a fixed `MIME -> extension` map, ensuring the extension matches the validated type rather than the original filename. The storage path is also moved from `/var/www/html/uploads/` (inside the webroot, where files are directly executable) to `/var/uploads/` (outside the webroot). File writes use `StandardOpenOption.CREATE_NEW`, which fails if the file already exists, preventing race-condition overwrites. A size limit is enforced, and an empty-file check guards against null-byte attacks or zero-byte uploads.

## Behaviour changes

- **Imports added**: Tika, NIO `Files`/`Path`/`Paths`/`StandardOpenOption`, `HashSet`, `Set`, `UUID`, and `java.util.Map` are imported to support content detection, safe file operations, and random filename generation.
- **Static state added**: `ALLOWED_TYPES` (allowlist), `TIKA` (detector instance), and `EXTENSION_MAP` (MIME-to-extension mapping) are added as class members and initialized in a static block. These are configuration constants that support validation and safe filename derivation.
- **Error handling**: The method now throws `IllegalArgumentException` for empty files, disallowed types, and oversized files. These are checked before file I/O to fail fast. This replaces the original contract, which allowed any file and only threw `IOException` if the write itself failed.
- **Storage path**: Changed from `/var/www/html/uploads/` to `/var/uploads/` (outside webroot). Prevents direct execution of uploaded files by web server.
- **Filename generation**: Changed from `file.getOriginalFilename()` to `UUID.randomUUID() + extension`. The original filename is completely discarded; the client can no longer influence the storage path.
- **File I/O**: Changed from `file.transferTo(destination)` (which copies the stream directly) to `Files.write(uploadPath, fileBytes, StandardOpenOption.CREATE_NEW)` (which reads bytes into memory, validates them, and writes atomically). This adds memory overhead and requires bytes to fit in heap, but enables in-memory content detection. For large files, consider buffering or streaming Tika detection; for typical web uploads (a few MB), this is acceptable.
- **Return value**: Unchanged in shape, still returns the upload path as a string, but now the path is random and outside the web root.

These changes trade the original "accept and store any file under its original name" contract for "accept only allowlisted types under a random name, outside the webroot, with size limits." The trade-off is intentional and closes the CWE-434 weakness.
