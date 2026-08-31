## Verdict

**Exploitable.** The application accepts uploaded files without validating type, size, or content, and stores them using the client-supplied filename directly in a web-accessible directory. An attacker can upload malicious executables (e.g., `.jsp`, `.php`) or path traversal sequences to compromise the system.

## Source

`MultipartFile file` parameter from the HTTP request at line 17.

## Fix

**Dependency addition (pom.xml):**

Add Apache Tika for content detection:
```xml
<dependency>
    <groupId>org.apache.tika</groupId>
    <artifactId>tika-core</artifactId>
    <version>2.9.1</version>
</dependency>
```

**Fixed code:**

```java
package evalcases;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.apache.tika.Tika;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@RestController
public class MultipartUploadNoValidation {

    private static final String UPLOAD_DIR = "/var/uploads/"; // Outside webroot
    private static final long MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB limit
    private static final Set<String> ALLOWED_TYPES = new HashSet<>();
    private static final Map<String, String> MIME_TO_EXT = new HashMap<>();
    
    static {
        // Allowlist of permitted MIME types
        ALLOWED_TYPES.add("image/jpeg");
        ALLOWED_TYPES.add("image/png");
        ALLOWED_TYPES.add("image/gif");
        ALLOWED_TYPES.add("image/webp");
        ALLOWED_TYPES.add("application/pdf");
        
        // Map detected MIME types to safe file extensions
        MIME_TO_EXT.put("image/jpeg", ".jpg");
        MIME_TO_EXT.put("image/png", ".png");
        MIME_TO_EXT.put("image/gif", ".gif");
        MIME_TO_EXT.put("image/webp", ".webp");
        MIME_TO_EXT.put("application/pdf", ".pdf");
    }

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        // Validate file size
        if (file.getSize() > MAX_FILE_SIZE) {
            throw new IllegalArgumentException("File exceeds maximum size of " + MAX_FILE_SIZE + " bytes");
        }
        if (file.getSize() == 0) {
            throw new IllegalArgumentException("File is empty");
        }
        
        // Detect actual file type from content bytes
        Tika tika = new Tika();
        String detectedType = tika.detect(file.getInputStream());
        
        // Validate against allowlist of permitted types
        if (!ALLOWED_TYPES.contains(detectedType)) {
            throw new IllegalArgumentException("File type not permitted: " + detectedType);
        }
        
        // Generate safe filename: random UUID + extension from detected type
        String safeExtension = MIME_TO_EXT.get(detectedType);
        if (safeExtension == null || safeExtension.isEmpty()) {
            throw new IllegalArgumentException("No safe extension for type: " + detectedType);
        }
        
        String safeFilename = UUID.randomUUID().toString() + safeExtension;
        
        // Ensure upload directory exists
        Path uploadPath = Paths.get(UPLOAD_DIR);
        Files.createDirectories(uploadPath);
        
        // Write file with atomic operation (CREATE_NEW fails if file exists)
        Path destination = uploadPath.resolve(safeFilename);
        Files.copy(file.getInputStream(), destination, StandardOpenOption.CREATE_NEW);
        
        return "Uploaded to " + destination.toAbsolutePath();
    }
}
```

## Explanation

The original code at line 21 (`file.transferTo(destination)`) accepts files without validation, trusts the client-supplied filename for storage, and writes to a web-accessible directory. This permits an attacker to upload executable scripts or use path traversal sequences.

The fix applies CWE-434 mitigation in four layers:

1. **Content validation**: Tika detects the actual file type by inspecting the byte signature (magic bytes), not the filename or client-supplied Content-Type header.

2. **Type allowlist**: Only MIME types in `ALLOWED_TYPES` are permitted; detection results outside this set are rejected.

3. **Safe filename generation**: A random UUID replaces the original filename, eliminating path traversal risks. The file extension is derived from the detected MIME type via `MIME_TO_EXT`, not the client-supplied filename—the extension controls how the server later serves the file, so client control here would still enable type confusion.

4. **File size enforcement**: A configurable size limit (`MAX_FILE_SIZE`) rejects oversized uploads before processing.

Storage is moved outside the webroot (`/var/uploads/` rather than `/var/www/html/uploads/`), preventing direct web server execution. The file is written with `StandardOpenOption.CREATE_NEW`, which atomically fails if the filename already exists, eliminating race conditions during concurrent uploads of the same UUID (astronomically unlikely but properly handled).

## Behaviour changes

- **Rejected file types**: Files detected as executable (`.exe`, `.jsp`, `.php`, etc.) are rejected; uploaders receive clear error messages.
- **Filename transformation**: Stored files no longer retain the uploaded filename; they receive UUIDs with detected extensions instead. Clients receiving the response will see absolute filesystem paths rather than recognizable names.
- **Size limits enforced**: Uploads exceeding 5MB are rejected before processing.
- **Path traversal blocked**: Sequences like `../` in the original filename cannot escape the upload directory.
- **Directory creation**: The upload directory is created automatically if missing.
- **Atomic writes**: Concurrent uploads cannot race to create the same filename (CREATE_NEW throws).
