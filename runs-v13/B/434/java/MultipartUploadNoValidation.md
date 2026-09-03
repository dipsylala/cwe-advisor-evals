## Verdict

Exploitable. An attacker can upload a malicious JSP, PHP, or executable script that the web server will execute directly because the code trusts the client-supplied filename and stores the file in a web-accessible directory without validating content type.

## Source

`MultipartFile file` parameter (untrusted HTTP request), specifically:
- `file.getOriginalFilename()` - client-supplied filename from the HTTP request
- `file.getContentType()` - client-supplied Content-Type header (not used in this code but would be unsafe)

## Sink

`file.transferTo(destination)` at line 21 writes the unvalidated upload to a path under `/var/www/html/uploads/`, a web-accessible directory.

## Fix

**Vulnerable code:**
```java
@PostMapping("/upload")
public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
    String originalFilename = file.getOriginalFilename();
    File destination = new File(UPLOAD_DIR + originalFilename);
    file.transferTo(destination);
    return "Uploaded to " + destination.getAbsolutePath();
}
```

**Fixed code:**
```java
import org.apache.tika.Tika;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@RestController
public class MultipartUploadNoValidation {

    private static final String UPLOAD_DIR = "/var/uploads/"; // Outside webroot
    private static final Set<String> ALLOWED_TYPES = Set.of("image/jpeg", "image/png", "application/pdf");
    private static final Map<String, String> MIME_TO_EXT = new HashMap<>();
    
    static {
        MIME_TO_EXT.put("image/jpeg", ".jpg");
        MIME_TO_EXT.put("image/png", ".png");
        MIME_TO_EXT.put("application/pdf", ".pdf");
    }

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        // Read file bytes for content detection
        byte[] fileBytes = file.getBytes();
        
        // Detect real file type from bytes using Tika
        Tika tika = new Tika();
        String detectedType = tika.detect(fileBytes);
        
        // Validate against allowlist
        if (!ALLOWED_TYPES.contains(detectedType)) {
            throw new IOException("File type not allowed: " + detectedType);
        }
        
        // Get extension from detected type (not from client-supplied filename)
        String extension = MIME_TO_EXT.get(detectedType);
        if (extension == null || extension.isEmpty()) {
            throw new IOException("Unknown extension for type: " + detectedType);
        }
        
        // Generate random filename, never use client-supplied name
        String filename = UUID.randomUUID().toString() + extension;
        Path destination = Paths.get(UPLOAD_DIR, filename);
        
        // Ensure directory exists and write with CREATE_NEW
        Files.createDirectories(destination.getParent());
        Files.write(destination, fileBytes, StandardOpenOption.CREATE_NEW);
        
        return "Uploaded to " + destination.toAbsolutePath();
    }
}
```

**Library recommendation:**

Add Apache Tika to the project. In `pom.xml`:
```xml
<dependency>
    <groupId>org.apache.tika</groupId>
    <artifactId>tika-core</artifactId>
</dependency>
```

Configure Spring multipart size limits in `application.properties`:
```properties
spring.servlet.multipart.max-file-size=10MB
spring.servlet.multipart.max-request-size=50MB
```

## Explanation

The fix addresses three critical flaws in the original code. First, it detects the actual file type by inspecting file bytes with Apache Tika (`tika.detect(fileBytes)`), not by trusting the client-supplied filename or Content-Type header—both are easily forged. Second, it validates the detected type against a server-maintained allowlist and rejects anything not explicitly permitted. Third, it breaks the taint chain by using only the allowlist-matched extension (`MIME_TO_EXT.get(detectedType)`) and a server-generated random filename (`UUID.randomUUID()`) for storage, never passing the untrusted original filename downstream. The file is now stored outside the web root (`/var/uploads/` instead of `/var/www/html/uploads/`), so even if it is somehow executable, the web server cannot reach it via HTTP. The `StandardOpenOption.CREATE_NEW` flag ensures the file is created fresh and fails if it already exists, preventing race conditions. Together, these changes eliminate the ability to upload and execute arbitrary code.

## Behaviour changes

- **Directory change**: Files are now stored in `/var/uploads/` (outside the webroot) instead of `/var/www/html/uploads/` (inside the webroot). This prevents web server execution or direct serving of the uploaded files. Reason: core CWE-434 fix—executable files must not be web-accessible.
- **Filename change**: Client-supplied `getOriginalFilename()` is no longer used; files are now stored with a random UUID-based name (e.g., `550e8400-e29b-41d4-a716-446655440000.jpg`). Reason: original filename may contain path traversal sequences or reveal attacker intent; random naming prevents both.
- **Extension derivation**: File extension is now derived from the Tika-detected content type via a fixed allowlist map, not from the client-supplied filename. Reason: prevents extension spoofing (e.g., uploading `shell.jpg` that is actually a JSP file).
- **New validation gate**: Unrecognized or disallowed file types now throw `IOException` and reject the upload entirely. Reason: enforces the server's business rules and closes the upload vector for dangerous types.
- **Bytes loaded into memory**: `file.getBytes()` loads the entire file into memory for Tika detection before writing. For very large files, this may increase memory usage. Mitigation: enforce size limits via `spring.servlet.multipart.max-file-size` and tune the JVM heap if needed. Reason: Tika's detection requires access to file bytes; streaming detection is not available in tika-core's basic API.
- **Directory creation**: `Files.createDirectories()` ensures the parent directory exists before writing. If the storage directory is read-only or unmounted, this may throw `IOException`. Reason: defensive—creates the upload directory on first use if it does not exist.
- **Return value unchanged**: The method still returns a success message with the stored path. Reason: no change to the contract; the caller receives the absolute path where the file was stored.
