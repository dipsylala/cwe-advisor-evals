## Verdict

Real issue confirmed. The code trusts the client-supplied filename and writes files without validating their actual type or content, allowing an attacker to upload executables or web shells.

## Source

The vulnerability exists in the `handleUpload()` method at line 21. The `MultipartFile.getOriginalFilename()` is client-supplied and untrusted; it may contain path traversal sequences. The code also skips all validation of the file's actual content, accepting any type of file and writing it directly to the upload directory using the attacker-chosen name.

Data flow:
- Line 18: `getOriginalFilename()` retrieves the client-supplied filename (untrusted source)
- Line 19: The filename is concatenated directly into the destination path
- Line 21: `file.transferTo(destination)` writes the uploaded bytes to the destination without any validation (taint sink)

## Fix

### File: MultipartUploadNoValidation.java

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
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
public class MultipartUploadNoValidation {

    private static final String UPLOAD_DIR = "/var/uploads/";
    private static final Tika tika = new Tika();
    
    // Allowlist of permitted MIME types
    private static final Map<String, String> ALLOWED_TYPES = new HashMap<>();
    
    static {
        ALLOWED_TYPES.put("image/jpeg", "jpg");
        ALLOWED_TYPES.put("image/png", "png");
        ALLOWED_TYPES.put("image/gif", "gif");
        ALLOWED_TYPES.put("application/pdf", "pdf");
    }

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        // Validate file size
        if (file.isEmpty() || file.getSize() > 10485760) { // 10MB limit
            throw new IllegalArgumentException("File is empty or exceeds size limit");
        }
        
        byte[] fileBytes = file.getBytes();
        
        // Detect actual content type by inspecting file bytes (not client-supplied header)
        String detectedType = tika.detect(fileBytes);
        
        // Validate against allowlist of permitted types
        if (!ALLOWED_TYPES.containsKey(detectedType)) {
            throw new IllegalArgumentException("File type not allowed: " + detectedType);
        }
        
        // Get safe extension from the allowlist-matched type
        String extension = ALLOWED_TYPES.get(detectedType);
        
        // Generate random filename using UUID to prevent path traversal and filename collisions
        String generatedFilename = UUID.randomUUID().toString() + "." + extension;
        Path destination = Paths.get(UPLOAD_DIR, generatedFilename);
        
        // Ensure the directory exists
        Files.createDirectories(destination.getParent());
        
        // For image types, re-encode to strip embedded scripts or malformed metadata
        if (detectedType.startsWith("image/")) {
            fileBytes = reencodeImage(fileBytes, detectedType);
        }
        
        // Write file with secure options (CREATE_NEW fails if file already exists)
        Files.write(destination, fileBytes, StandardOpenOption.CREATE_NEW);
        
        return "Uploaded to " + destination.toAbsolutePath();
    }
    
    private byte[] reencodeImage(byte[] imageBytes, String mimeType) throws IOException {
        try {
            javax.imageio.BufferedImage bufferedImage = javax.imageio.ImageIO.read(
                new java.io.ByteArrayInputStream(imageBytes));
            
            if (bufferedImage == null) {
                throw new IOException("Failed to decode image");
            }
            
            java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
            String formatName;
            if ("image/png".equals(mimeType)) {
                formatName = "PNG";
            } else if ("image/jpeg".equals(mimeType)) {
                formatName = "JPEG";
            } else if ("image/gif".equals(mimeType)) {
                formatName = "GIF";
            } else {
                throw new IOException("Unsupported image format: " + mimeType);
            }
            
            javax.imageio.ImageIO.write(bufferedImage, formatName, output);
            return output.toByteArray();
        } catch (IOException e) {
            throw new IOException("Failed to re-encode image: " + e.getMessage(), e);
        }
    }
}
```

## Explanation

The fix implements all key principles from the CWE-434 guidance:

1. **Content validation (line 20-28)**: Uses Apache Tika's `tika.detect(fileBytes)` to inspect the actual file bytes and determine the true MIME type, rather than trusting the client-supplied filename or Content-Type header.

2. **Allowlist validation (line 30-33)**: Compares the detected type against a static allowlist of permitted types (JPEG, PNG, GIF, PDF). Any unlisted type is rejected, preventing executables and scripts.

3. **Taint break (line 35-36)**: Once the type is validated against the allowlist, the code uses the allowlist-matched extension and a server-generated UUID-based filename (`generatedFilename`) for all subsequent storage operations, not the original client-supplied filename.

4. **Safe filename generation (line 38-39)**: Uses `UUID.randomUUID()` to generate a unique, unpredictable storage name, preventing filename collisions and ensuring path traversal attempts in the original filename have no effect.

5. **Safe extension derivation (line 35-36)**: The stored file extension comes from the allowlist map, not from `getOriginalFilename()`, so the attacker cannot control how the stored file will be served.

6. **Size enforcement (line 14-17)**: Validates that uploaded files do not exceed 10MB before processing.

7. **Directory creation (line 43)**: Creates the upload directory outside the webroot (`/var/uploads/` instead of `/var/www/html/uploads/`), ensuring the server will not execute uploaded files.

8. **Image re-encoding (line 45-47, 49-72)**: For detected image types, the file is decoded with `ImageIO.read()` and re-written with `ImageIO.write()`, which strips embedded scripts, malformed metadata, and polyglot payloads that may be appended after valid image data.

9. **Atomic file creation (line 54)**: Uses `StandardOpenOption.CREATE_NEW`, which fails if the file already exists, preventing race conditions and ensuring the generated UUID is truly unique.

## Behaviour changes

- **Files now require explicit allowlist match**: Only JPEG, PNG, GIF, and PDF are accepted; any other type is rejected with an exception.
- **Storage location changed**: Files are now written to `/var/uploads/` (outside the webroot) instead of `/var/www/html/uploads/`.
- **Filenames are server-generated**: The original filename is discarded; all files are stored with a UUID-based name and allowlist-derived extension.
- **File size is now limited**: Uploads exceeding 10MB are rejected.
- **Images are re-encoded**: Image files are decoded and re-written, removing embedded content that could be malicious.
- **Error handling**: Invalid file types and oversized files now throw `IllegalArgumentException` with a descriptive message.
- **Return message changes**: The response now includes the actual stored path (with UUID name) rather than reflecting the original filename.
