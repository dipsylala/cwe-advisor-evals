## Verdict

CONFIRMED. The code accepts and saves uploaded files without validating the file extension, MIME type, or filename, allowing an attacker to upload dangerous file types (executables, scripts, archives) to a web-accessible directory.

## Source

Line 21: `file.transferTo(destination);`

The sink is preceded by unsafe construction of the destination path on line 19, where `originalFilename` (attacker-controlled) is concatenated directly into the file path without any validation or sanitization. This allows uploading files with arbitrary extensions to a web directory where they may be executed or exploited.

## Fix

```java
package evalcases;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.util.Set;
import java.util.UUID;

@RestController
public class MultipartUploadNoValidation {

    private static final String UPLOAD_DIR = "/var/www/html/uploads/";
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of("pdf", "doc", "docx", "txt", "jpg", "jpeg", "png");
    private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        // Validate file size
        if (file.getSize() > MAX_FILE_SIZE) {
            throw new IllegalArgumentException("File size exceeds maximum limit");
        }

        // Validate file extension
        String originalFilename = file.getOriginalFilename();
        if (originalFilename == null || !originalFilename.contains(".")) {
            throw new IllegalArgumentException("Invalid filename");
        }

        String extension = originalFilename.substring(originalFilename.lastIndexOf(".") + 1).toLowerCase();
        if (!ALLOWED_EXTENSIONS.contains(extension)) {
            throw new IllegalArgumentException("File type not allowed");
        }

        // Generate safe filename using UUID to prevent directory traversal and collisions
        String safeFilename = UUID.randomUUID().toString() + "." + extension;
        File destination = new File(UPLOAD_DIR + safeFilename);

        file.transferTo(destination);
        return "Uploaded to " + destination.getAbsolutePath();
    }
}
```

## Explanation

The remediation applies three layers of defence:

1. **File size validation** (line 26-28): Reject files exceeding 10 MB before processing to prevent resource exhaustion.

2. **Extension whitelist** (line 32-37): Extract and validate the file extension against a hardcoded set of safe types. Reject any file with an extension outside this list (e.g., `.exe`, `.jsp`, `.sh`). This prevents uploading executable or script files that could be executed by the server or a downstream process.

3. **Safe filename generation** (line 39-40): Replace the user-supplied filename with a server-generated UUID, preserving only the validated extension. This eliminates directory traversal risks (e.g., `../../../etc/passwd`) and ensures filename collisions don't overwrite existing files.

The allowed extensions set should be tailored to your application's actual needs — add only document and image types required for your use case, never executable or script extensions.
