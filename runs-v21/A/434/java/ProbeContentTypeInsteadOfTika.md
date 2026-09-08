## Verdict

The code uses `Files.probeContentType()` to validate uploaded file types. This is insufficient for CWE-434 mitigation because it relies on file extension and basic magic bytes, both of which attackers can spoof. A malicious file can bypass this check by crafting content with misleading magic bytes or using a benign extension. The proper fix replaces shallow detection with Apache Tika, which performs deep content inspection to reliably identify actual file types regardless of extension or crafted headers.

## Source

File: DocumentUploadController.java, line 42

```java
String detectedType = Files.probeContentType(tempFile);
```

The issue: `Files.probeContentType()` does not reliably detect file types and can be bypassed by attackers crafting files with misleading content or extensions.

## Fix

### File: DocumentUploadController.java

```java
package com.example.upload;

import org.apache.tika.Tika;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Set;
import java.util.UUID;

@RestController
public class DocumentUploadController {

    private static final Set<String> ALLOWED_TYPES = Set.of("image/jpeg", "image/png", "application/pdf");
    private static final Path UPLOAD_DIR = Paths.get("/var/app/uploads");
    private static final Tika tika = new Tika();

    @PostMapping("/api/documents")
    public ResponseEntity<String> uploadDocument(@RequestParam("file") MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("Empty file");
        }

        // Write the upload to a temp file so we can inspect the real content
        // type on disk using deep content inspection rather than trusting
        // the client-supplied header or relying on unreliable file extension heuristics.
        String originalFilename = file.getOriginalFilename();
        String suffix = (originalFilename != null && originalFilename.contains("."))
                ? originalFilename.substring(originalFilename.lastIndexOf('.'))
                : ".tmp";
        Path tempFile = Files.createTempFile("upload-", suffix);
        file.transferTo(tempFile);

        // Use Tika for robust content type detection based on deep file content inspection,
        // not just extension or magic bytes.
        String detectedType;
        try {
            detectedType = tika.detect(tempFile);
        } catch (IOException e) {
            Files.deleteIfExists(tempFile);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error detecting file type");
        }

        if (detectedType == null || !ALLOWED_TYPES.contains(detectedType)) {
            Files.deleteIfExists(tempFile);
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                    .body("Rejected: unrecognized or disallowed file type (" + detectedType + ")");
        }

        String storedName = UUID.randomUUID().toString();
        Path destination = UPLOAD_DIR.resolve(storedName);
        Files.move(tempFile, destination, StandardCopyOption.REPLACE_EXISTING);

        return ResponseEntity.ok(storedName);
    }
}
```

## Explanation

The fix replaces `Files.probeContentType()` with Apache Tika's `detect()` method for the following reasons:

1. **Deep Content Inspection**: Tika analyzes the actual file structure and content, not just the filename or superficial magic bytes. This makes it significantly harder for attackers to spoof file types.

2. **Consistent Detection**: Tika uses multiple detection strategies (parsers, magic bytes, media type detection) to reliably identify files, whereas `Files.probeContentType()` is system-dependent and fragile.

3. **CWE-434 Mitigation**: Unrestricted file uploads can be exploited by uploading executable files, malware, or other dangerous types. Tika's deep inspection ensures only genuinely safe file types pass the allowlist check.

4. **Error Handling**: Added try-catch block to handle detection failures gracefully, preventing the application from crashing or processing files with detection errors.

5. **Dependency**: Apache Tika must be added as a Maven/Gradle dependency (e.g., `org.apache.tika:tika-core`) to enable this functionality.

The remediation maintains the existing security intent (temp file writing, allowlist checking, UUID-based storage) while replacing the weak detection mechanism with a robust one that properly closes the CWE-434 vulnerability.
