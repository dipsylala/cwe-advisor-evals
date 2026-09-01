## Verdict

The vulnerability is confirmed. The application uploads user-supplied files without validating their type, extension, or MIME type, allowing attackers to upload and potentially execute arbitrary code.

## Source

**Vulnerable Code (Line 21):**
```java
file.transferTo(destination);
```

The sink is the `transferTo()` call, which writes the multipart file to disk using the user-supplied `originalFilename` without any filtering or validation of file type.

**Root Cause:**
- No whitelist validation of file extensions or MIME types
- Direct use of user-supplied filename in the upload path
- No file size validation

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
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@RestController
public class MultipartUploadNoValidation {

    private static final String UPLOAD_DIR = "/var/www/html/uploads/";
    private static final long MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB
    private static final Set<String> ALLOWED_EXTENSIONS = new HashSet<>(Arrays.asList(
        "pdf", "jpg", "jpeg", "png", "gif", "doc", "docx", "txt"
    ));
    private static final Set<String> ALLOWED_MIME_TYPES = new HashSet<>(Arrays.asList(
        "application/pdf",
        "image/jpeg",
        "image/png",
        "image/gif",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "text/plain"
    ));

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        // Validate file is not empty
        if (file.isEmpty()) {
            throw new IllegalArgumentException("File is empty");
        }

        // Validate file size
        if (file.getSize() > MAX_FILE_SIZE) {
            throw new IllegalArgumentException("File exceeds maximum size of " + MAX_FILE_SIZE + " bytes");
        }

        // Validate MIME type
        String contentType = file.getContentType();
        if (contentType == null || !ALLOWED_MIME_TYPES.contains(contentType)) {
            throw new IllegalArgumentException("File type not allowed: " + contentType);
        }

        // Validate file extension
        String originalFilename = file.getOriginalFilename();
        if (originalFilename == null || !originalFilename.contains(".")) {
            throw new IllegalArgumentException("Invalid filename");
        }

        String extension = originalFilename.substring(originalFilename.lastIndexOf(".") + 1).toLowerCase();
        if (!ALLOWED_EXTENSIONS.contains(extension)) {
            throw new IllegalArgumentException("File extension not allowed: " + extension);
        }

        // Generate a safe filename using UUID to prevent directory traversal and overwrite attacks
        String safeFilename = UUID.randomUUID().toString() + "." + extension;
        Path uploadPath = Paths.get(UPLOAD_DIR, safeFilename).normalize();

        // Ensure the resolved path is still within the upload directory
        Path uploadDir = Paths.get(UPLOAD_DIR).normalize();
        if (!uploadPath.startsWith(uploadDir)) {
            throw new IllegalArgumentException("Invalid upload path");
        }

        File destination = uploadPath.toFile();
        file.transferTo(destination);
        return "Uploaded to " + destination.getAbsolutePath();
    }
}
```

## Explanation

The fix implements defense-in-depth validation before any file is written:

1. **File Size Validation**: Rejects files exceeding 5 MB to prevent disk exhaustion attacks.

2. **MIME Type Validation**: Checks the `Content-Type` header against a whitelist of safe types. This prevents execution of scripts and malicious code.

3. **Extension Validation**: Extracts and validates the file extension against a whitelist of safe extensions. Extensions are converted to lowercase to prevent bypass via mixed-case tricks.

4. **Safe Filename Generation**: Replaces the user-supplied filename with a UUID-based name, preserving only the validated extension. This prevents:
   - Directory traversal via path sequences like `../`
   - Filename-based attacks (null bytes, special characters)
   - Overwriting existing files

5. **Path Normalization and Verification**: Uses `Path.normalize()` and `startsWith()` to ensure the resolved upload path remains within the intended upload directory, preventing symlink or traversal escapes.

All validation occurs before the `transferTo()` sink, ensuring only safe, whitelisted files reach the filesystem.

