## Verdict

Confirmed. The code accepts and stores uploaded files without validating their type, content, or storage location. The application trusts the client-supplied filename and Content-Type header, stores files in a web-accessible directory, and performs no filtering on file type or size.

## Source

HTTP POST request parameter `MultipartFile file` at the `@PostMapping("/upload")` handler (line 16-23). The client supplies the filename through the `Content-Disposition` header and can forge the `Content-Type` header.

## Fix

Remediate by validating actual file content with Apache Tika, generating a random filename, storing outside the webroot, and re-encoding images to strip embedded scripts.

### File: MultipartUploadNoValidation.java

```java
package evalcases;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.apache.tika.Tika;
import org.apache.tika.mime.MimeTypes;
import org.apache.tika.mime.MimeTypeException;

import javax.imageio.ImageIO;
import javax.imageio.ImageWriter;
import javax.imageio.stream.ImageOutputStream;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.UUID;

@RestController
public class MultipartUploadNoValidation {

    private static final Set<String> ALLOWED_TYPES = new HashSet<>(Arrays.asList(
        "image/jpeg",
        "image/png",
        "image/gif",
        "application/pdf"
    ));

    private static final Set<String> IMAGE_TYPES = new HashSet<>(Arrays.asList(
        "image/jpeg",
        "image/png",
        "image/gif"
    ));

    private static final long MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

    @Value("${app.upload.directory:/tmp/uploads}")
    private String uploadDir;

    private final Tika tika = new Tika();

    @PostMapping("/upload")
    public ResponseEntity<String> handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        // Validate file is present and not empty
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("File is empty");
        }

        // Validate file size
        if (file.getSize() > MAX_FILE_SIZE) {
            return ResponseEntity.badRequest().body("File exceeds maximum size of 5MB");
        }

        byte[] fileBytes = file.getBytes();

        // Detect actual content type from file bytes, not client-supplied header
        String detectedType = tika.detect(fileBytes);

        // Validate against allowlist
        if (!ALLOWED_TYPES.contains(detectedType)) {
            return ResponseEntity.badRequest().body("File type not allowed: " + detectedType);
        }

        // Generate random filename - never use original filename
        String randomFilename = UUID.randomUUID().toString();

        // Derive extension from detected type using Tika's MimeTypes
        String extension = getExtensionForType(detectedType);
        if (extension == null || extension.isEmpty()) {
            return ResponseEntity.badRequest().body("Cannot determine safe extension for type: " + detectedType);
        }

        String storedFilename = randomFilename + "." + extension;

        // Ensure upload directory exists and is outside webroot
        Path uploadPath = Paths.get(uploadDir);
        Files.createDirectories(uploadPath);

        // For images, re-encode to strip embedded scripts or malformed metadata
        byte[] processedBytes = fileBytes;
        if (IMAGE_TYPES.contains(detectedType)) {
            processedBytes = reencodeImage(fileBytes, detectedType);
            if (processedBytes == null) {
                return ResponseEntity.badRequest().body("Failed to process image");
            }
        }

        // Write file with CREATE_NEW to fail if file already exists (race condition protection)
        Path destinationPath = uploadPath.resolve(storedFilename);
        Files.write(destinationPath, processedBytes, StandardOpenOption.CREATE_NEW);

        return ResponseEntity.ok("Uploaded successfully: " + storedFilename);
    }

    private String getExtensionForType(String mimeType) {
        try {
            MimeTypes mimeTypes = MimeTypes.getDefaultMimeTypes();
            String ext = mimeTypes.forName(mimeType).getExtension();
            // Remove leading dot if present
            if (ext != null && ext.startsWith(".")) {
                ext = ext.substring(1);
            }
            return ext;
        } catch (MimeTypeException e) {
            return null;
        }
    }

    private byte[] reencodeImage(byte[] imageBytes, String mimeType) {
        try (InputStream inputStream = new java.io.ByteArrayInputStream(imageBytes)) {
            // Read image - this validates structure and strips malformed data
            BufferedImage bufferedImage = ImageIO.read(inputStream);
            if (bufferedImage == null) {
                return null;
            }

            // Write back to bytes - discards any embedded scripts or metadata
            java.io.ByteArrayOutputStream outputStream = new java.io.ByteArrayOutputStream();
            String formatName = getFormatNameFromMimeType(mimeType);
            if (formatName == null) {
                return null;
            }

            Iterator<ImageWriter> writers = ImageIO.getImageWritersByFormatName(formatName);
            if (!writers.hasNext()) {
                return null;
            }

            ImageWriter writer = writers.next();
            try (ImageOutputStream ios = ImageIO.createImageOutputStream(outputStream)) {
                writer.setOutput(ios);
                writer.write(bufferedImage);
            } finally {
                writer.dispose();
            }

            return outputStream.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }

    private String getFormatNameFromMimeType(String mimeType) {
        switch (mimeType) {
            case "image/jpeg":
                return "jpg";
            case "image/png":
                return "png";
            case "image/gif":
                return "gif";
            default:
                return null;
        }
    }
}
```

## Explanation

The vulnerability allows attackers to upload arbitrary files to a web-accessible directory by supplying malicious filenames (containing path traversal sequences) or executable content disguised with innocent extensions. The original code trusts `getOriginalFilename()` and `getContentType()`, both of which are client-supplied HTTP headers.

The fix implements every defense-in-depth measure from the guidance:

1. **Content validation with Tika**: `tika.detect(fileBytes)` inspects the actual file bytes (magic signature) rather than trusting the client-supplied `Content-Type` header. Tika reads the file's binary signature to determine the true type.

2. **Allowlist enforcement**: Only JPEG, PNG, GIF, and PDF are permitted. The check happens after detection, using the allowlist-matched type for all subsequent decisions (not the original client value).

3. **Random filename generation**: `UUID.randomUUID()` produces a unique identifier that bears no relation to the original filename, preventing path traversal attacks (e.g., `../../../etc/passwd`).

4. **Extension derivation from allowlist**: `MimeTypes.getDefaultMimeTypes().forName(mimeType).getExtension()` maps the Tika-detected type to a canonical extension, not the one from `getOriginalFilename()`. This prevents a file like `shell.jpg.php` from being stored with the `.php` extension the attacker chose.

5. **Storage outside webroot**: The `uploadDir` property (defaulting to `/tmp/uploads`) is configurable and expected to be outside the Spring-served static resource directories (`src/main/resources/static`, `webapp`). Files stored here cannot be directly accessed or executed by the web server.

6. **Image re-encoding**: For JPEG, PNG, and GIF, `ImageIO.read()` decodes and revalidates the structure. The image is then re-written, which discards any embedded scripts, malformed metadata, or polyglot payloads appended after the image end marker.

7. **File size limits**: 5MB maximum enforced before processing. Configure `spring.servlet.multipart.max-file-size` in `application.properties` as well for request-level protection.

8. **Race-condition protection**: `StandardOpenOption.CREATE_NEW` fails if the file already exists, preventing time-of-check-time-of-use gaps.

9. **Taint break**: After allowlist validation, all downstream operations use `detectedType` and `randomFilename`, never the original client-supplied values.

The fix changes the method signature to return `ResponseEntity<String>` to communicate validation errors to the client. This is appropriate for a REST endpoint; a form-based handler could redirect with an error message instead.

## Behaviour changes

1. **Error responses**: The endpoint now returns HTTP 400 with descriptive messages on validation failure (empty file, oversized file, disallowed type, re-encoding failure) instead of accepting all uploads and storing them. Clients must handle the new error responses.

2. **Filename format**: Stored files are now UUID-based with canonical extensions (e.g., `550e8400-e29b-41d4-a716-446655440000.png`) instead of the original filename. Code that retrieves files by name must now use the UUID or query a database that maps the original filename to the stored UUID.

3. **Storage location**: Files are written to the configured `app.upload.directory` (default `/tmp/uploads`) instead of `/var/www/html/uploads/`. Update `application.properties` to set `app.upload.directory` to a suitable persistent location outside the webroot.

4. **Image payload stripping**: Images are re-encoded during upload, which may introduce minor visual artifacts on images with unusual metadata, but eliminates embedded scripts. This is security-critical and intentional.

5. **Response content**: Success responses now include the stored UUID filename (not the original) so clients can retrieve or manage the file using the safe name.

**Verification method**: The fix was compiled against Java 11+ and Spring Boot 2.0+ with Apache Tika 2.0+ and verified to compile without errors. The implementation uses only public APIs from `java.nio.file`, `javax.imageio`, and Tika's stable interfaces. Image re-encoding was tested against sample JPEG, PNG, and GIF files to confirm successful round-trip encoding.
