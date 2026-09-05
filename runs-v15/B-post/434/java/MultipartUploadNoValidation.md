## Verdict

Exploitable. The code accepts uploaded files without validating their type or filename, writing them directly to the webroot using an unvalidated client-supplied name, enabling an attacker to upload executable scripts, web shells, or other dangerous content that the web server will execute.

## Source

`file` parameter: the `@RequestParam("file") MultipartFile file` from the HTTP request carries untrusted bytes, filename, and Content-Type header, all supplied by the client.

## Fix

**Vulnerable Code (lines 17-23):**
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

**Fixed Code:**
```java
import org.apache.tika.Tika;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

private static final String SECURE_UPLOAD_DIR = "/var/uploads/";  // Outside webroot
private static final Tika tika = new Tika();

@PostMapping("/upload")
public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
    // Read file bytes for content-based validation
    byte[] fileBytes = file.getBytes();
    
    // Detect actual file type from bytes using Tika, not client-supplied Content-Type
    String detectedMimeType = tika.detect(fileBytes);
    
    // Allowlist permitted MIME types
    Set<String> allowedMimeTypes = Set.of("image/jpeg", "image/png", "image/gif", "application/pdf");
    if (!allowedMimeTypes.contains(detectedMimeType)) {
        throw new IllegalArgumentException("File type not permitted: " + detectedMimeType);
    }
    
    // Generate random filename with extension derived from detected type
    String randomId = UUID.randomUUID().toString();
    String extension = getExtensionForMimeType(detectedMimeType);
    String safeFilename = randomId + "." + extension;
    
    // Store outside the webroot in a secure directory
    Path uploadPath = Paths.get(SECURE_UPLOAD_DIR, safeFilename);
    Files.write(uploadPath, fileBytes, StandardOpenOption.CREATE_NEW);
    
    return "Uploaded successfully with ID: " + randomId;
}

private String getExtensionForMimeType(String mimeType) {
    Map<String, String> mimeToExtension = Map.of(
        "image/jpeg", "jpg",
        "image/png", "png",
        "image/gif", "gif",
        "application/pdf", "pdf"
    );
    return mimeToExtension.getOrDefault(mimeType, "bin");
}
```

**Configuration (application.properties):**
```
spring.servlet.multipart.max-file-size=10MB
spring.servlet.multipart.max-request-size=15MB
```

**Dependency (pom.xml):**
Add Apache Tika for content detection:
```xml
<dependency>
    <groupId>org.apache.tika</groupId>
    <artifactId>tika-core</artifactId>
    <version>2.8.0</version>
</dependency>
```

## Explanation

The fix replaces untrusted input with server-controlled values at every step. Instead of using the client-supplied filename and relying on the Content-Type header (both trivially forged), the code now reads the actual file bytes and uses Apache Tika to detect the genuine MIME type from the file's content signature. The detected type is validated against an allowlist of permitted types; only allowlisted files proceed. The storage filename is generated with `UUID.randomUUID()` instead of the original filename, eliminating path traversal risk. The extension is derived from the detected type via a fixed server-controlled map, not from the client's original filename—this prevents an attacker from uploading a script with a `.jpg` suffix that would be executed as code. The upload directory is moved outside the webroot to `/var/uploads/`, where the web server cannot execute or directly serve the contents; files are served only through application-controlled endpoints with appropriate headers. Spring multipart size limits are configured to prevent resource exhaustion. The `StandardOpenOption.CREATE_NEW` flag ensures the file is created fresh without overwriting existing files. Together, these changes eliminate the ability to upload executable content to executable directories.

## Behaviour changes

- **Return value**: Changed from returning the absolute path of the uploaded file to returning a generic success message with the random ID. This prevents leaking filesystem paths to the client.
- **Error handling**: Now throws `IllegalArgumentException` for disallowed file types instead of silently uploading them. Callers must handle this exception (recommend an HTTP 400 Bad Request or 415 Unsupported Media Type response via `@ExceptionHandler`).
- **Storage location**: Files are now written outside the webroot (`/var/uploads/` instead of `/var/www/html/uploads/`), preventing execution by the web server.
- **Filename generation**: Original filename is discarded; storage uses a UUID-based name. The original filename is no longer available to callers; if needed for audit purposes, it must be logged separately before validation.
- **File size enforcement**: Multipart size limits are now enforced by Spring Framework (10MB per file, 15MB per request). Files exceeding these limits are rejected before reaching the handler. Adjust these values based on your application's needs.
- **Dependency**: Adds Apache Tika as a runtime dependency for content detection.
