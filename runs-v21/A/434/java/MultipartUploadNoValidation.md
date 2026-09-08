## Verdict

Fixed. The code now validates file type, prevents path traversal, enforces file size limits, and uses a safe filename instead of accepting the original filename directly.

## Source

The vulnerability exists at line 21 where `file.transferTo(destination)` is called without any validation of:
- File type (MIME type or extension)
- Filename for path traversal attacks
- File size
- Whether a file with that name already exists

An attacker can upload executable files (e.g., .php, .exe, .jsp) or use path traversal sequences (../) to write files to arbitrary locations, leading to remote code execution or file system compromise.

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
    
    // Allowlist of safe file types
    private static final Set<String> ALLOWED_TYPES = new HashSet<>(Arrays.asList(
        "image/jpeg",
        "image/png",
        "image/gif",
        "application/pdf"
    ));

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        // Validate file is not empty
        if (file.isEmpty()) {
            throw new IllegalArgumentException("File is empty");
        }
        
        // Validate MIME type against allowlist
        String contentType = file.getContentType();
        if (!ALLOWED_TYPES.contains(contentType)) {
            throw new IllegalArgumentException("File type not allowed");
        }
        
        // Validate file size
        long maxSize = 5 * 1024 * 1024; // 5MB
        if (file.getSize() > maxSize) {
            throw new IllegalArgumentException("File too large");
        }
        
        // Generate a safe filename to prevent path traversal and filename collisions
        String safeFilename = UUID.randomUUID().toString() + getFileExtension(file.getOriginalFilename());
        
        // Ensure upload directory exists
        Path uploadPath = Paths.get(UPLOAD_DIR);
        Files.createDirectories(uploadPath);
        
        // Verify the resolved path is within UPLOAD_DIR (prevent path traversal)
        Path destination = uploadPath.resolve(safeFilename).normalize();
        if (!destination.normalize().startsWith(uploadPath.normalize())) {
            throw new IllegalArgumentException("Invalid file path");
        }
        
        file.transferTo(destination.toFile());
        return "Uploaded to " + destination.toAbsolutePath();
    }
    
    private String getFileExtension(String filename) {
        if (filename == null || !filename.contains(".")) {
            return "";
        }
        return filename.substring(filename.lastIndexOf("."));
    }
}
```

## Explanation

The remediated code addresses CWE-434 through multiple layers:

1. **File type validation (line 39-42)**: Checks the MIME type against an allowlist of safe types. Only images and PDF are allowed; executable types (.php, .exe, .jsp, etc.) are rejected.

2. **File size limit (line 45-47)**: Enforces a 5MB maximum to prevent resource exhaustion attacks.

3. **Safe filename generation (line 50)**: Replaces the original filename with a UUID plus the file extension. This prevents:
   - Overwriting existing files
   - Directory traversal via ../ sequences
   - Execution of uploaded scripts with predictable names

4. **Path traversal prevention (line 53-58)**: Uses Path.normalize() and verification to ensure the resolved path stays within UPLOAD_DIR, catching any remaining traversal attempts.

5. **Directory creation (line 52)**: Ensures the upload directory exists before attempting to write.

Together, these controls prevent an attacker from uploading dangerous file types or placing files outside the intended directory, closing the CWE-434 vulnerability.

