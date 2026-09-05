## Verdict

VULNERABLE. The code uses `Files.probeContentType()` at line 42 to validate uploaded file types. On JDK 9+, this method inspects the filename (extension-to-MIME lookup) rather than the file's actual bytes. Since the temporary file was created with the client-supplied file extension preserved (line 38), an attacker can upload a malicious executable (e.g., a shell script or binary) with a spoofed `.pdf` or `.jpg` extension and bypass the allowlist validation. The file passes the check and is stored, where it could be executed or served with incorrect MIME type handling.

## Source

- Input: `MultipartFile file` parameter from HTTP POST request, lines 25 and 34
- Client-controlled data: `file.getOriginalFilename()` extracted at line 34
- Intermediate: Temporary file created at line 38 with the client's original filename suffix
- Sink: `Files.probeContentType(tempFile)` at line 42, which validates file type based on filename, not content

## Fix

**Library Requirement:**

Add `org.apache.tika:tika-core` to your project's Maven or Gradle dependencies. The guidance does not prescribe a specific minimum version; confirm the resolved version against your SCA/dependency-check tooling before merging.

**Fixed Code:**

```java
package com.example.upload;

import org.apache.tika.Tika;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@RestController
public class DocumentUploadController {

    private static final Set<String> ALLOWED_TYPES = Set.of("image/jpeg", "image/png", "application/pdf");
    private static final Path UPLOAD_DIR = Paths.get("/var/app/uploads");
    
    // Map detected MIME types to safe file extensions
    private static final Map<String, String> MIME_TO_EXT = Map.ofEntries(
            Map.entry("image/jpeg", ".jpg"),
            Map.entry("image/png", ".png"),
            Map.entry("application/pdf", ".pdf")
    );
    
    private static final Tika tika = new Tika();

    @PostMapping("/api/documents")
    public ResponseEntity<String> uploadDocument(@RequestParam("file") MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("Empty file");
        }

        // Write the upload to a temp file without preserving the client's suffix.
        // This prevents probeContentType (which keys off filenames) from being
        // fooled; we use Tika to inspect the actual bytes instead.
        Path tempFile = Files.createTempFile("upload-", ".tmp");
        file.transferTo(tempFile);

        // Detect the actual file type from its bytes using Tika, not from
        // the client-supplied filename or Content-Type header.
        byte[] fileBytes = Files.readAllBytes(tempFile);
        String detectedType = tika.detect(fileBytes);

        if (detectedType == null || !ALLOWED_TYPES.contains(detectedType)) {
            Files.deleteIfExists(tempFile);
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                    .body("Rejected: unrecognized or disallowed file type (" + detectedType + ")");
        }

        // For images, re-encode to strip embedded scripts or malformed metadata.
        // Detection identifies only the prefix; a polyglot PNG with appended script
        // still detects as image/png, so re-encoding discards non-pixel data.
        if (detectedType.startsWith("image/")) {
            BufferedImage img = ImageIO.read(tempFile.toFile());
            if (img == null) {
                Files.deleteIfExists(tempFile);
                return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                        .body("Rejected: invalid image file");
            }
            String format = detectedType.equals("image/jpeg") ? "jpg" : "png";
            ImageIO.write(img, format, tempFile.toFile());
        }

        // Generate a random filename with the Tika-detected extension,
        // not the client-supplied filename.
        String storedName = UUID.randomUUID().toString() + MIME_TO_EXT.get(detectedType);
        Path destination = UPLOAD_DIR.resolve(storedName);
        Files.move(tempFile, destination, StandardCopyOption.REPLACE_EXISTING);

        return ResponseEntity.ok(storedName);
    }
}
```

## Explanation

The original code trusted `Files.probeContentType()` to validate file type. On JDK 9+, this method performs extension-to-MIME lookup against the filename, not content inspection. Because the temporary file was created with the client's original extension, an attacker could upload a malicious executable renamed with a benign extension (e.g., `shell.sh` as `shell.pdf`) and pass the validation.

The fix replaces this with Apache Tika's `tika.detect(bytes)`, which inspects the file's actual content bytes to determine the MIME type. This closes the extension-spoofing attack because Tika reads the file signature (magic bytes) and structural properties, not the filename.

The temporary file is now created without a client-supplied suffix to prevent accidental re-use of the extension anywhere. The validated MIME type is then used to look up a safe file extension from a fixed `MIME_TO_EXT` map, ensuring the stored file's extension matches its actual content and cannot be chosen by the attacker.

For image uploads, the code re-encodes the image using `ImageIO`, which discards metadata and any payload appended after the image structure. Detection alone does not remove embedded scripts (a polyglot PNG with script appended still detects as `image/png`), so re-encoding is required to guarantee safety.

## Behaviour changes

1. **Content type detection now inspects bytes, not filenames**: Tika's byte-based detection replaces the filename-based lookup, eliminating extension spoofing attacks. Files with mismatched extension and content are now rejected unless the content matches the allowlist.

2. **Stored extensions are derived from actual content, not client input**: The filename extension is now selected from `MIME_TO_EXT` based on Tika's detection result, not copied from the client-supplied filename. This prevents attackers from controlling the file's served extension.

3. **Image files are re-encoded before storage**: Images are decoded and re-written using `ImageIO`, stripping embedded metadata, scripts, or polyglot payloads. This is necessary because signature-based detection does not remove content that follows valid image structure.

4. **Temporary files no longer preserve client suffixes**: The temp file is created with a generic `.tmp` suffix instead of the client's original extension, preventing any reliance on filename during intermediate checks.

5. **Dependency addition**: Apache Tika (`tika-core`) is now required as a Maven/Gradle dependency.

