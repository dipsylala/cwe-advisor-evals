# CWE-434 Remediation Report

## Verdict

**Exploitable** - high confidence

The vulnerability at line 21 (`file.transferTo(destination)`) is exploitable. The application accepts file uploads without validating file type by content, generates no random filename, and stores uploads in a web-accessible directory (`/var/www/html/uploads/`). An attacker can upload an executable script (`.jsp`, `.php`, `.aspx`) or web shell masquerading as an innocent file type, reach the file through the web server, and execute arbitrary code.

## Source

**Source:** `file.getOriginalFilename()` (line 18) - client-supplied HTTP header, untrusted

**Sink:** `file.transferTo(destination)` (line 21) - writes file to disk in webroot

**Location:** `MultipartUploadNoValidation.java:21`

**Data Flow:**
1. HTTP request provides `MultipartFile` with client-supplied filename in `getOriginalFilename()`
2. Filename is concatenated directly with `UPLOAD_DIR` constant pointing to webroot
3. `transferTo()` writes uploaded bytes to the constructed path
4. Web server serves the file from webroot and executes or displays it based on extension

## Fix

### File: MultipartUploadNoValidation.java

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
import java.nio.file.StandardOpenOption;
import java.util.Set;
import java.util.UUID;

import org.apache.tika.Tika;
import org.apache.tika.mime.MimeTypeException;
import org.apache.tika.mime.MimeTypes;

@RestController
public class MultipartUploadNoValidation {

    // Storage directory outside webroot
    private static final String UPLOAD_DIR = "/var/uploads/";

    // Allowlist of permitted MIME types
    private static final Set<String> ALLOWED_TYPES = Set.of(
        "image/png",
        "image/jpeg",
        "image/gif",
        "application/pdf",
        "text/plain"
    );

    private static final Tika tika = new Tika();
    private static final MimeTypes mimeTypes = MimeTypes.getDefaultMimeTypes();

    private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        // Enforce file size limit
        if (file.getSize() > MAX_FILE_SIZE) {
            throw new IllegalArgumentException("File exceeds maximum size");
        }

        // Detect actual content type from file bytes
        byte[] fileBytes = file.getBytes();
        String detectedType = tika.detect(fileBytes);

        // Validate against allowlist
        if (!ALLOWED_TYPES.contains(detectedType)) {
            throw new IllegalArgumentException("File type not permitted: " + detectedType);
        }

        // Generate random filename with extension from detected type
        String extension = getExtensionForType(detectedType);
        String randomFilename = UUID.randomUUID().toString() + extension;

        // Store outside webroot
        Path uploadPath = Paths.get(UPLOAD_DIR, randomFilename);
        Files.createDirectories(uploadPath.getParent());

        // Write with CREATE_NEW to prevent overwrite attacks
        Files.write(uploadPath, fileBytes, StandardOpenOption.CREATE_NEW);

        return "Uploaded to " + uploadPath.toAbsolutePath();
    }

    private static String getExtensionForType(String mimeType) throws IOException {
        try {
            String ext = mimeTypes.forName(mimeType).getExtension();
            if (ext == null || ext.isEmpty()) {
                throw new IOException("Unknown extension for type: " + mimeType);
            }
            return ext;
        } catch (MimeTypeException e) {
            throw new IOException("Invalid MIME type: " + mimeType, e);
        }
    }
}
```

## Explanation

The fix eliminates CWE-434 by implementing four core defenses from the guidance:

**1. Content-based file type validation:** Instead of trusting the client-supplied `getOriginalFilename()` or `getContentType()` headers, the fix uses Apache Tika (`org.apache.tika:tika-core`) to inspect the actual file bytes and detect the true MIME type via `tika.detect(fileBytes)`. This prevents disguised executables.

**2. Allowlist validation:** The detected type is checked against `ALLOWED_TYPES`, a fixed set of permitted MIME types. Rejection happens before any file operations. An attacker uploading a `.jsp` executable will be rejected at this gate, not permitted based on an extension check.

**3. Storage outside webroot:** Files are written to `/var/uploads/` instead of `/var/www/html/uploads/`, placing them outside the web server's static resource directories. Even if an executable somehow landed here, it would not be served or executed via HTTP requests.

**4. Random filename generation:** The stored filename is generated using `UUID.randomUUID()` plus a server-derived extension. The original filename—which may contain path traversal sequences like `../` or dangerous extensions—is discarded. A `@.jsp` payload in the filename cannot influence how the file is later served because the filename is entirely server-controlled.

The fix uses `Files.write(..., StandardOpenOption.CREATE_NEW)` to atomically reject attempts to create a file that already exists (preventing race-condition overwrites), and `Files.createDirectories()` to ensure the parent directory exists. The `getExtensionForType()` helper maps the Tika-detected MIME type to the canonical extension, guarding against `null` or empty extension values that would produce malformed filenames.

## Behaviour changes

**File size enforcement:** The original code had no limit; the fixed code enforces a maximum of 10 MB via `MAX_FILE_SIZE`. This is defensive hardening and does not affect legitimate uploads under this threshold. The value should be tuned to the application's actual upload requirements.

**Error handling:** The original code silently accepted any file. The fixed code throws `IllegalArgumentException` for oversized files or disallowed types. Callers will receive HTTP 400 errors instead of successful responses for rejected uploads, allowing client-side logic to display appropriate error messages.

**Return value:** Both versions return a string message with the file path. The original returns the potentially unsafe user-supplied filename via `destination.getAbsolutePath()`; the fixed version returns the server-generated path, which is safe.

**Storage location change:** Files are now written to `/var/uploads/` (outside webroot) instead of `/var/www/html/uploads/` (inside webroot). If the application previously served uploaded files by directly accessing them as static resources, serving logic must be updated to fetch files from the new storage directory and return them through application-controlled HTTP responses (e.g., with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff` headers). This prevents the web server from executing scripts and enforces the application's own access controls.

**Dependency addition:** The fix introduces Apache Tika (`org.apache.tika:tika-core`) as a runtime dependency. This must be added to the project's build configuration (e.g., `pom.xml` for Maven, `build.gradle` for Gradle). No specific version constraint is needed beyond confirming the library is maintained and up-to-date against SCA tooling; the guidance provides no version floor for this library.

