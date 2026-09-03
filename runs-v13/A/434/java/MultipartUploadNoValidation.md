## Verdict

CONFIRMED. The code accepts file uploads without validating file type or extension, allowing attackers to upload executable files or scripts that could be executed on the server.

## Source

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
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of("pdf", "doc", "docx", "txt", "jpg", "jpeg", "png", "gif");
    private static final Set<String> DANGEROUS_EXTENSIONS = Set.of("exe", "bat", "cmd", "com", "jar", "jsp", "jspx", "jspf", "sh", "bash", "pl", "php", "asp", "aspx", "cgi", "py", "rb", "class");

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        // Validate file is not empty
        if (file.isEmpty()) {
            throw new IllegalArgumentException("File cannot be empty");
        }
        
        String originalFilename = file.getOriginalFilename();
        if (originalFilename == null || originalFilename.isEmpty()) {
            throw new IllegalArgumentException("Invalid filename");
        }
        
        // Extract file extension
        String extension = getFileExtension(originalFilename).toLowerCase();
        
        // Reject dangerous extensions
        if (DANGEROUS_EXTENSIONS.contains(extension)) {
            throw new IllegalArgumentException("File type not allowed: " + extension);
        }
        
        // Validate against whitelist
        if (!ALLOWED_EXTENSIONS.contains(extension)) {
            throw new IllegalArgumentException("File type not allowed");
        }
        
        // Generate safe filename using UUID to prevent path traversal
        String safeFilename = UUID.randomUUID().toString() + "." + extension;
        File destination = new File(UPLOAD_DIR + safeFilename);
        
        file.transferTo(destination);
        return "Uploaded to " + destination.getAbsolutePath();
    }
    
    private String getFileExtension(String filename) {
        int lastDot = filename.lastIndexOf(".");
        if (lastDot > 0 && lastDot < filename.length() - 1) {
            return filename.substring(lastDot + 1);
        }
        return "";
    }
}
```

## Explanation

The vulnerability was caused by uploading files without validation of file type or extension. The fix implements multiple layers of defense:

1. **Whitelist validation**: Only allow specific safe file extensions (`pdf`, `doc`, `docx`, `txt`, `jpg`, `jpeg`, `png`, `gif`) that are unlikely to execute on the server.

2. **Dangerous extension blacklist**: Explicitly reject known dangerous extensions (executables, scripts, and server-side interpreters like `exe`, `jsp`, `sh`, `php`, `asp`, `py`, etc.) to catch evasion attempts.

3. **Safe filename generation**: Use `UUID.randomUUID()` to generate a unique, unpredictable filename instead of trusting the user-supplied filename. This prevents path traversal attacks (e.g., `../../evil.jsp`) and filename-based attacks.

4. **Input validation**: Check that the file is not empty and has a valid filename before processing.

The fix prioritizes whitelist validation over blacklist alone, as blacklists are easier to evade with new or obfuscated extensions. By generating a UUID-based filename with only the validated extension appended, the uploaded file cannot be executed even if the server misconfigures its MIME type handling.
