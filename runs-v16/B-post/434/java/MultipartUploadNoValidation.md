## Verdict
exploitable

## Source
The `file` parameter in the `handleUpload()` method is a Spring `MultipartFile` injected from an HTTP request. Attackers control the file content, original filename, and Content-Type header.

## Fix

### Vulnerable Code
```java
@PostMapping("/upload")
public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
    String originalFilename = file.getOriginalFilename();
    File destination = new File(UPLOAD_DIR + originalFilename);
    // CWE-434: No validation of file type or content
    // Uses client-supplied filename directly as storage path
    // Stores in web-accessible directory
    file.transferTo(destination);
    return "Uploaded to " + destination.getAbsolutePath();
}
```

### Fixed Code
```java
package evalcases;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.apache.tika.Tika;
import org.apache.tika.mime.MimeTypes;
import org.apache.tika.mime.MimeTypeException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@RestController
public class MultipartUploadNoValidation {

    // Store outside webroot - path should be configured externally
    private static final String UPLOAD_DIR = "/var/data/uploads/";
    
    // Allowlist of permitted MIME types
    private static final Set<String> ALLOWED_TYPES = new HashSet<>();
    static {
        ALLOWED_TYPES.add("image/jpeg");
        ALLOWED_TYPES.add("image/png");
        ALLOWED_TYPES.add("image/gif");
        ALLOWED_TYPES.add("application/pdf");
    }

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        // Validate file is not empty
        if (file.isEmpty() || file.getSize() == 0) {
            throw new IOException("File is empty");
        }

        // Detect actual content type from file bytes using Tika
        // Never rely on client-supplied getContentType() or getOriginalFilename()
        Tika tika = new Tika();
        byte[] fileBytes = file.getBytes();
        String detectedType = tika.detect(fileBytes);
        
        // Validate detected type against allowlist
        if (!ALLOWED_TYPES.contains(detectedType)) {
            throw new IOException("File type not allowed: " + detectedType);
        }

        // Generate random filename using UUID - never use original filename
        String filename = UUID.randomUUID().toString();
        
        // Derive extension from detected type via Tika's type registry
        // Ignore client-supplied extension entirely
        String extension = getExtensionForType(detectedType);
        String storedFilename = filename + "." + extension;
        
        // Store in non-webroot directory with generated name
        Path uploadPath = Paths.get(UPLOAD_DIR, storedFilename);
        
        // Write with CREATE_NEW to fail if file exists (should not happen with UUID)
        Files.write(uploadPath, fileBytes, StandardOpenOption.CREATE_NEW);
        
        return "Uploaded to " + uploadPath.toAbsolutePath();
    }
    
    private String getExtensionForType(String mimeType) throws IOException {
        try {
            MimeTypes mimeTypes = MimeTypes.getDefaultMimeTypes();
            String ext = mimeTypes.forName(mimeType).getExtension();
            
            // Tika may return null or empty string for unknown extensions
            if (ext == null || ext.isEmpty()) {
                throw new IOException("No extension mapping for type: " + mimeType);
            }
            
            // Remove leading dot if Tika included one
            return ext.startsWith(".") ? ext.substring(1) : ext;
        } catch (MimeTypeException e) {
            throw new IOException("Failed to map MIME type to extension: " + mimeType, e);
        }
    }
}
```

Application configuration (in `application.properties`):
```
spring.servlet.multipart.max-file-size=5MB
spring.servlet.multipart.max-request-size=10MB
```

Maven dependency (add to `pom.xml`):
```xml
<dependency>
    <groupId>org.apache.tika</groupId>
    <artifactId>tika-core</artifactId>
    <version>2.9.1</version>
</dependency>
```

## Explanation
The fix closes CWE-434 by implementing three layers of defense: content-based type validation, generated storage names, and non-webroot storage. The vulnerable code passed the attacker-controlled `getOriginalFilename()` directly to `transferTo()`, accepting any extension and path component. An attacker could upload `shell.jsp` or `../../../etc/evil.txt` to traverse directories or place executable content in the webroot.

The fixed code detects the actual file type from bytes using Apache Tika (resistant to extension/Content-Type spoofing), checks it against an allowlist of business-required types, and stores the file with a random UUID-based name whose extension is derived from the detected type via `MimeTypes.forName()`. The storage directory is moved outside the web-accessible tree (`/var/data/uploads/` instead of `/var/www/html/uploads/`), and Spring's multipart size limits are configured to prevent resource exhaustion.

The allowlist and extension mapping ensure that even if an attacker embeds one file type inside another (polyglot), the stored extension will not match the embedded content, and the allowlist check prevents dangerous types entirely. UUID generation and `StandardOpenOption.CREATE_NEW` eliminate filename collision and traversal attacks.

## Behaviour changes

- **Storage path changed**: Files now store outside webroot (`/var/data/uploads/` instead of `//var/www/html/uploads/`). This is necessary to prevent web server execution of uploads. Downstream code serving files must read from the new directory.
- **Filename format changed**: Original filename replaced with UUID; original filename is now discarded. Clients cannot predict or retrieve files by guessing names, but will need a retrieval mechanism mapping UUIDs to upload records.
- **Extension derivation**: Extension comes from Tika-detected type, not client-supplied original filename. A `.jpg` file with PNG data will be stored as `.png`, breaking any assumption that stored extension matches input extension.
- **File size validation**: `spring.servlet.multipart.max-file-size` config enforces a 5MB limit (configurable). Requests exceeding this are rejected before reaching the handler. Original code had no limit.
- **Type mismatch rejection**: Files with mismatched extension and content (e.g., `malware.pdf` containing executable code) are rejected if the detected type is not in the allowlist. Original code accepted anything.
- **Response message**: Returns the new storage path with UUID, not the original path. Any code parsing or logging this response will see a different format.
- **Empty file rejection**: Code now explicitly rejects empty files. Original code accepted them.

## Verification

**Syntax check**: Java syntax verified with `javac` 26. Code compiles syntactically; runtime dependencies (Spring Framework, Apache Tika 2.9.1) required at build/runtime as declared in pom.xml. No new APIs beyond what the CWE-434 guidance specifies.

**New APIs used**:
- `org.apache.tika.Tika` (from Apache Tika 2.9.1)
- `org.apache.tika.mime.MimeTypes` (from Apache Tika 2.9.1)
- `org.apache.tika.mime.MimeTypeException` (from Apache Tika 2.9.1)
- `java.util.UUID` (standard library)
- `java.nio.file.Files`, `Path`, `Paths`, `StandardOpenOption` (standard library)
- Existing Spring APIs: `MultipartFile`, `@PostMapping`, `@RequestParam` (already in original code)
