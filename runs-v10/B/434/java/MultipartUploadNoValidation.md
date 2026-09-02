## Verdict

Exploitable. Line 21 writes untrusted file content to the webroot based on an untrusted filename supplied by the client. An attacker can upload an executable file type (e.g., `.jsp`, `.jspx`, `.html` with `<script>`) and access it directly via HTTP, causing the server to execute the uploaded code.

## Source

Line 18: `String originalFilename = file.getOriginalFilename();`

`getOriginalFilename()` returns the client-supplied `filename=` parameter from the multipart request header, which is trivially forged and not validated by the server.

## Fix

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
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@RestController
public class MultipartUploadNoValidation {

    // Storage directory OUTSIDE webroot to prevent direct execution
    private static final String STORAGE_DIR = "/var/storage/uploads/";
    
    // Allowlist of permitted MIME types
    private static final Set<String> ALLOWED_TYPES = new HashSet<>(Arrays.asList(
        "image/jpeg",
        "image/png",
        "image/gif",
        "application/pdf"
    ));

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        // Detect actual file type from content bytes using Tika
        byte[] fileBytes = file.getBytes();
        Tika tika = new Tika();
        String detectedType = tika.detect(fileBytes);
        
        // Validate detected type against allowlist
        if (!ALLOWED_TYPES.contains(detectedType)) {
            throw new IllegalArgumentException("File type not allowed: " + detectedType);
        }
        
        // Generate random filename; derive extension from detected type, not original filename
        String extension = getExtensionForType(detectedType);
        String storedFilename = UUID.randomUUID().toString() + "." + extension;
        Path destination = new File(STORAGE_DIR + storedFilename).toPath();
        
        // Write file outside webroot using CREATE_NEW to prevent overwrites
        Files.write(destination, fileBytes, StandardOpenOption.CREATE_NEW);
        
        return "Uploaded successfully";
    }
    
    private String getExtensionForType(String mimeType) {
        switch (mimeType) {
            case "image/jpeg": return "jpg";
            case "image/png": return "png";
            case "image/gif": return "gif";
            case "application/pdf": return "pdf";
            default: return "bin";
        }
    }
}
```

## Explanation

The fix closes CWE-434 by enforcing three controls at once:

1. **Content validation**: Apache Tika inspects the actual file bytes (not the client-supplied filename extension or Content-Type header) to detect the real MIME type. The detected type is then validated against an allowlist of business-required types (images and PDFs in this example), rejecting all others.

2. **Random storage filename**: The original filename is discarded entirely. A new filename is generated using `UUID.randomUUID()`, preventing both path traversal sequences in the original filename and allowing the attacker to control the extension or path.

3. **Storage outside webroot**: The file is written to `/var/storage/uploads/` instead of `/var/www/html/uploads/`, placing it outside the web server's static resource directory where it cannot be directly accessed or executed by an HTTP request. The extension is derived from the allowlist-validated type using a fixed map, not from the client-supplied filename.

The write uses `StandardOpenOption.CREATE_NEW` to atomically fail if a collision occurs (extremely rare with UUID v4, but a safety measure against denial-of-service).

## Behaviour changes

- **Storage location changed**: Files now write to `/var/storage/uploads/` (outside webroot) instead of `/var/www/html/uploads/` (inside webroot). The endpoint no longer returns the absolute path; it returns a static success message. Callers that relied on the returned path must be refactored to track uploads in a database or service layer.
- **File format changed**: Writes now use `Files.write()` with `StandardOpenOption.CREATE_NEW` instead of `MultipartFile.transferTo()`. This is a semantically equivalent operation (both write bytes to the filesystem) but provides atomic failure on collision instead of silently overwriting.
- **Exception behavior changed**: Invalid file types now throw `IllegalArgumentException` instead of accepting and storing the file. Oversized files still raise an exception from `file.getBytes()`, but earlier in the handler. Callers must be prepared to catch and handle these validation exceptions in a REST advice class or filter.
- **Dependency added**: Requires Apache Tika (`org.apache.tika:tika-core`) as a classpath dependency. The exact version must be confirmed against SCA/dependency-check tooling before merging.
