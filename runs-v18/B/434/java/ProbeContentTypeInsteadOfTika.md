## Verdict
CONFIRMED. The finding at line 42 is a real vulnerability. `Files.probeContentType()` on JDK 9+ is unreliable for content validation because it keys off the filename extension (which the attacker controls via the original filename) rather than inspecting actual file bytes. An attacker can upload executable code with a safe-looking extension (e.g., `malware.exe` as `malware.pdf`), and `Files.probeContentType()` will report the type based on `.pdf`, not content. The fix requires replacing this with Apache Tika's content-based detection.

## Source
`MultipartFile` parameter at line 25 (`@RequestParam("file") MultipartFile file`). The attacker controls the original filename via HTTP request headers, and the file content is arbitrary binary data.

## Fix
### File: DocumentUploadController.java

```java
package com.example.upload;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.apache.tika.Tika;
import org.apache.tika.mime.MimeTypes;
import org.apache.tika.mime.MimeTypeException;

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
        // type by examining actual file bytes, not the client-supplied header.
        Path tempFile = Files.createTempFile("upload-", ".tmp");
        file.transferTo(tempFile);

        try {
            // Detect the actual file type from content bytes using Tika.
            // Files.probeContentType() is unreliable on JDK 9+ as it keys off
            // filename extension rather than content.
            String detectedType = tika.detect(tempFile);

            if (detectedType == null || !ALLOWED_TYPES.contains(detectedType)) {
                Files.deleteIfExists(tempFile);
                return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                        .body("Rejected: unrecognized or disallowed file type (" + detectedType + ")");
            }

            // Derive the stored extension from the allowlist-matched type,
            // not from the client-supplied filename.
            String storedName = UUID.randomUUID().toString();
            String extension;
            try {
                MimeTypes mimeTypes = MimeTypes.getDefaultMimeTypes();
                org.apache.tika.mime.MimeType mimeType = mimeTypes.forName(detectedType);
                extension = mimeType.getExtension();
                if (extension == null || extension.isEmpty()) {
                    extension = ".bin";
                }
            } catch (MimeTypeException e) {
                Files.deleteIfExists(tempFile);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Error processing file type");
            }

            storedName = storedName + extension;
            Path destination = UPLOAD_DIR.resolve(storedName);
            Files.move(tempFile, destination, StandardCopyOption.REPLACE_EXISTING);

            return ResponseEntity.ok(storedName);
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }
}
```

## Explanation
The original code attempted to use `Files.probeContentType()` to validate uploaded file types against an allowlist. However, this method is fundamentally unreliable for security validation on JDK 9+: it performs filename-based detection (extension-to-MIME-type lookup) rather than inspecting actual file bytes. The guidance for CWE-434 explicitly states this gap and prescribes Apache Tika for content-based detection.

The fix replaces `Files.probeContentType()` with `Tika.detect()`, which reads the actual file bytes and infers the type from file signatures (magic bytes), not the filename. After validation, the code derives the stored file's extension from the Tika-detected (and allowlist-matched) type via `MimeTypes.getDefaultMimeTypes().forName(detectedType).getExtension()`, ensuring the filename no longer reflects client-controlled input. The temp file is created with a generic `.tmp` extension, and no client-supplied extension is preserved. If `getExtension()` returns null or empty (for types with no standard extension), the code defaults to `.bin`.

The fix also adds a finally block to clean up the temp file if any exception occurs after it is created, preventing resource leaks.

## Behaviour changes
- **Type detection**: Now inspects actual file bytes via Tika instead of keying off filename extension. An executable file masquerading as a PDF (e.g., `malware.exe` uploaded as `malware.pdf`) will now be rejected because Tika detects the true binary format.
- **Stored filename**: Previously stored files without an extension (e.g., `550e8400-e29b-41d4-a716-446655440000`). Now stores with an extension derived from the detected type (e.g., `550e8400-e29b-41d4-a716-446655440000.pdf`), which ensures the stored file's handling matches its actual content type when served.
- **Temp file naming**: Changed from using the client-supplied extension (e.g., `.pdf`) to a generic `.tmp`, removing the ability for attackers to influence type detection through filename tricks.
- **Error handling**: Added explicit handling for `MimeTypeException` if the detected type is not recognized by Tika's MIME type registry (unlikely in practice, but now returns HTTP 500 with a descriptive message rather than crashing).
- **Resource cleanup**: Added finally block to ensure temp files are deleted even if an unexpected exception occurs, reducing disk space waste from orphaned uploads.

**Required dependency**: This fix requires Apache Tika (`org.apache.tika:tika-core`). Add to `pom.xml` if not already present:
```xml
<dependency>
    <groupId>org.apache.tika</groupId>
    <artifactId>tika-core</artifactId>
    <!-- version must be determined from advisory or SCA tooling -->
</dependency>
```
