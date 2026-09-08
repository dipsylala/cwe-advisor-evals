## Verdict

The finding is confirmed. The upload handler trusts client-supplied filename and content-type headers without validation, stores files in the webroot, and performs no file type allowlisting. This enables arbitrary file upload and code execution.

## Source

The vulnerability spans lines 18-21 of the handler. Line 18 retrieves the untrusted original filename via `getOriginalFilename()`. Line 19 concatenates it directly into a path under the webroot. Line 21 writes the unvalidated file to that path.

```java
@PostMapping("/upload")
public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
    String originalFilename = file.getOriginalFilename();
    File destination = new File(UPLOAD_DIR + originalFilename);
    // SAST FINDING: CWE-434 - sink: file.transferTo(destination)
    // Unsafe pattern: no content type validation, original filename used as storage path,
    // storage inside webroot (/var/www/html/uploads/)
    file.transferTo(destination);
    return "Uploaded to " + destination.getAbsolutePath();
}
```

## Fix

### File: MultipartUploadNoValidation.java

```java
package evalcases;

import org.apache.tika.Tika;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@RestController
public class MultipartUploadNoValidation {

    // Store files outside the webroot, not in /var/www/html/
    private static final String UPLOAD_DIR = "/var/uploads/";
    
    // Allowlist of permitted MIME types based on business requirements
    private static final Set<String> ALLOWED_TYPES = new HashSet<>();
    static {
        ALLOWED_TYPES.add("image/jpeg");
        ALLOWED_TYPES.add("image/png");
        ALLOWED_TYPES.add("application/pdf");
    }
    
    private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
    private static final Tika tika = new Tika();

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        // Validate file size before processing
        if (file.getSize() > MAX_FILE_SIZE) {
            throw new IllegalArgumentException("File exceeds maximum size of " + MAX_FILE_SIZE);
        }
        
        // Read file content to validate against allowlist
        byte[] fileContent = file.getBytes();
        
        // Detect actual file type from content (not from client-supplied header)
        String detectedType = tika.detect(fileContent);
        
        // Validate against allowlist of permitted types
        if (!ALLOWED_TYPES.contains(detectedType)) {
            throw new IllegalArgumentException("File type " + detectedType + " is not allowed");
        }
        
        // Derive extension from detected type, never from original filename
        String extension = getExtensionForType(detectedType);
        
        // Generate random filename using UUID (do not use original client-supplied filename)
        String randomFilename = UUID.randomUUID().toString() + extension;
        File uploadDir = new File(UPLOAD_DIR);
        if (!uploadDir.exists()) {
            uploadDir.mkdirs();
        }
        
        File destination = new File(UPLOAD_DIR + randomFilename);
        
        // Write file with CREATE_NEW to prevent overwrites and path traversal via symlinks
        Files.write(destination.toPath(), fileContent, StandardOpenOption.CREATE_NEW);
        
        return "Uploaded to " + randomFilename;
    }
    
    /**
     * Map detected MIME type to safe file extension.
     * This allowlist prevents extension spoofing and ensures consistent handling.
     */
    private String getExtensionForType(String mimeType) {
        switch (mimeType) {
            case "image/jpeg":
                return ".jpg";
            case "image/png":
                return ".png";
            case "application/pdf":
                return ".pdf";
            default:
                throw new IllegalArgumentException("Unknown MIME type: " + mimeType);
        }
    }
}
```

## Explanation

The fix addresses all vectors of CWE-434:

**Content Type Validation**: Replaced trust in client-supplied `getContentType()` and `getOriginalFilename()` with Apache Tika's byte-level content detection via `tika.detect(fileContent)`. Tika inspects file magic bytes to determine the real type regardless of extension or header spoofing.

**Allowlist Enforcement**: Validated the detected type against a business-specific allowlist of permitted MIME types. Files not in the allowlist (e.g., executables, shell scripts, archives) are rejected before storage.

**Filename Generation**: Replaced the original client-supplied filename with a cryptographically random UUID via `UUID.randomUUID()`, eliminating path traversal attack vectors (e.g., `../../etc/passwd`, `.jsp` shells).

**Safe Storage Location**: Changed the storage directory from `/var/www/html/uploads/` (inside the webroot) to `/var/uploads/` (outside the webroot). This ensures uploaded content cannot be directly accessed or executed by the web server.

**Extension Derivation**: The stored file's extension is derived from the Tika-detected MIME type through a fixed allowlist map, not from the original filename. This prevents extension spoofing (e.g., `shell.jpg` that is actually an executable).

**File Size Limits**: Added validation that file size does not exceed a configured maximum (10MB), preventing disk exhaustion attacks.

**Atomic Write**: Used `Files.write()` with `StandardOpenOption.CREATE_NEW` instead of `transferTo()`. `CREATE_NEW` fails if the file already exists, preventing race conditions and symlink-following attacks.

**Dependency**: The fix requires Apache Tika (`org.apache.tika:tika-core`). Add to `pom.xml`:
```xml
<dependency>
    <groupId>org.apache.tika</groupId>
    <artifactId>tika-core</artifactId>
    <version>2.9.1</version>
</dependency>
```

## Behaviour changes

- **Accept**: Only files with MIME types in the allowlist (image/jpeg, image/png, application/pdf) are accepted. All other types are rejected with an error message.
- **Reject**: Files exceeding 10MB are rejected. Files with mismatched extension and content (e.g., `.jpg` containing shell script bytes) are rejected based on detected content.
- **Storage**: Files are written to `/var/uploads/` (configurable, outside webroot) instead of `/var/www/html/uploads/`. Filenames are randomized UUIDs with appropriate extensions.
- **Response**: The endpoint returns only the generated filename (e.g., `550e8400-e29b-41d4-a716-446655440000.jpg`) instead of the full path. This prevents information disclosure about the server's directory structure.
- **Error handling**: Upload failures now throw `IllegalArgumentException` for validation failures (unsupported type, oversized file) with descriptive messages, and `IOException` for disk write failures. Callers must handle these exceptions.
- **Path traversal**: Original filenames containing traversal sequences (e.g., `../../../etc/passwd`) are silently discarded and replaced with a safe random name. Symlink attacks via path construction are eliminated by using `Files.write()` with `CREATE_NEW` instead of `File.transferTo()`.
