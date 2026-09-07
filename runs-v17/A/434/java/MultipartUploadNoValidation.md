## Verdict

CONFIRMED. The code accepts and saves uploaded files without validating file type, extension, or filename safety. This allows attackers to upload arbitrary file types (executables, scripts) and potentially overwrite files via path traversal.

## Source

```java
@PostMapping("/upload")
public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
    String originalFilename = file.getOriginalFilename();
    File destination = new File(UPLOAD_DIR + originalFilename);
    file.transferTo(destination);  // Line 21: Sink - saves untrusted file without validation
    return "Uploaded to " + destination.getAbsolutePath();
}
```

The vulnerability stems from:
1. Using user-supplied `originalFilename` directly without validation
2. No file extension or MIME type whitelist
3. No filename sanitization; allows path traversal via `../` sequences
4. No file size limits
5. Direct file transfer without security checks

## Fix

### File: MultipartUploadNoValidation.java

```java
package evalcases;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@RestController
public class MultipartUploadNoValidation {

    private static final String UPLOAD_DIR = "/var/www/html/uploads/";
    private static final Set<String> ALLOWED_EXTENSIONS = new HashSet<>(
        Arrays.asList("pdf", "txt", "jpg", "jpeg", "png", "gif")
    );
    private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        // Validate file is not empty
        if (file.isEmpty()) {
            throw new IllegalArgumentException("File is empty");
        }

        // Validate file size
        if (file.getSize() > MAX_FILE_SIZE) {
            throw new IllegalArgumentException("File size exceeds maximum allowed size");
        }

        String originalFilename = file.getOriginalFilename();
        if (originalFilename == null || originalFilename.isEmpty()) {
            throw new IllegalArgumentException("Invalid filename");
        }

        // Extract and validate file extension
        String extension = getFileExtension(originalFilename);
        if (!ALLOWED_EXTENSIONS.contains(extension.toLowerCase())) {
            throw new IllegalArgumentException("File type not allowed");
        }

        // Generate safe filename using UUID to prevent directory traversal and collisions
        String safeFilename = UUID.randomUUID() + "." + extension;
        
        // Validate upload directory path and prevent directory traversal
        Path uploadDirPath = Paths.get(UPLOAD_DIR).toAbsolutePath();
        Path uploadPath = uploadDirPath.resolve(safeFilename).normalize();
        if (!uploadPath.startsWith(uploadDirPath)) {
            throw new IllegalArgumentException("Invalid file path");
        }

        File destination = uploadPath.toFile();
        file.transferTo(destination);
        return "Uploaded to " + destination.getAbsolutePath();
    }

    private String getFileExtension(String filename) {
        int lastDot = filename.lastIndexOf('.');
        if (lastDot > 0) {
            return filename.substring(lastDot + 1);
        }
        return "";
    }
}
```

## Explanation

The fix implements multiple layers of defense against CWE-434:

1. **Empty File Check**: Rejects empty uploads to prevent disk waste and potential bypass attempts.

2. **File Size Validation**: Enforces a maximum file size (10 MB) to prevent denial-of-service and resource exhaustion attacks.

3. **Extension Whitelist**: Validates the file extension against an allowed set (`pdf`, `txt`, `jpg`, `jpeg`, `png`, `gif`). Only files with these safe extensions are accepted; dangerous types like `.exe`, `.jsp`, `.php`, `.sh` are rejected at the source.

4. **Safe Filename Generation**: Instead of using the user-supplied `originalFilename`, the code generates a UUID-based filename and appends the validated extension. This eliminates several attack vectors:
   - Prevents overwriting existing files
   - Blocks directory traversal attempts (e.g., `../../etc/passwd.pdf`)
   - Prevents double-extension attacks (e.g., `file.pdf.exe`)
   - Avoids issues with special characters in filenames

5. **Path Traversal Prevention**: Uses `Path.normalize()` and `Path.startsWith()` to ensure the final file path remains within the upload directory, even if symbolic links or other tricks are used.

6. **Null/Empty Filename Handling**: Validates that `originalFilename` is not null or empty before processing, preventing null pointer exceptions and bypass attempts.

The fix converts an unrestricted upload sink into a secure upload handler that only accepts expected file types and stores them with safe, non-predictable filenames under a controlled directory.
