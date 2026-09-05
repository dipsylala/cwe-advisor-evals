## Verdict

**CWE-434: Unrestricted Upload of File with Dangerous Type** — The code uses `Files.probeContentType()` to detect file type from a temp file that retains the client-supplied extension. On JDK 9+, this method keys off the filename, not content bytes, allowing an attacker to upload executable or script content under a benign extension (e.g., shell script as `.jpg`) that bypasses validation. The stored filename uses a random UUID without a validated extension, providing no secondary defense.

## Source

File: `DocumentUploadController.java`, line 42

```java
String detectedType = Files.probeContentType(tempFile);
```

Contributing unsafe pattern: Lines 35–39 preserve the client's extension on the temp file, then line 42 probes based on that name. Lines 50–51 store with a UUID-only name, discarding extension entirely.

## Fix

Replace `Files.probeContentType()` with Apache Tika content detection. Map the detected type to a safe extension, and store the file with both the UUID and the validated extension.

**Dependency**: Add Apache Tika to the project.

**Maven (pom.xml)**:
```xml
<dependency>
    <groupId>org.apache.tika</groupId>
    <artifactId>tika-core</artifactId>
    <version>2.9.2</version>
</dependency>
```

**Fixed code**:

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
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@RestController
public class DocumentUploadController {

    private static final Set<String> ALLOWED_TYPES = Set.of("image/jpeg", "image/png", "application/pdf");
    private static final Path UPLOAD_DIR = Paths.get("/var/app/uploads");
    private static final Tika tika = new Tika();
    private static final Map<String, String> MIME_TO_EXT = Map.ofEntries(
            Map.entry("image/jpeg", ".jpg"),
            Map.entry("image/png", ".png"),
            Map.entry("application/pdf", ".pdf")
    );

    @PostMapping("/api/documents")
    public ResponseEntity<String> uploadDocument(@RequestParam("file") MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("Empty file");
        }

        // Write the upload to a temp file without preserving the client-supplied extension,
        // so we can inspect the real content from bytes, not the filename.
        Path tempFile = Files.createTempFile("upload-", ".tmp");
        file.transferTo(tempFile);

        // Detect real content type by inspecting file bytes with Tika, not by extension.
        String detectedType = tika.detect(tempFile);

        if (detectedType == null || !ALLOWED_TYPES.contains(detectedType)) {
            Files.deleteIfExists(tempFile);
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                    .body("Rejected: unrecognized or disallowed file type (" + detectedType + ")");
        }

        // Map the validated type to a safe extension; use only the allowlist-matched value.
        String extension = MIME_TO_EXT.get(detectedType);
        if (extension == null) {
            Files.deleteIfExists(tempFile);
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                    .body("Rejected: type not mapped to a valid extension");
        }

        // Generate a new filename with both UUID and validated extension.
        String storedName = UUID.randomUUID().toString() + extension;
        Path destination = UPLOAD_DIR.resolve(storedName);
        Files.move(tempFile, destination, StandardCopyOption.REPLACE_EXISTING);

        return ResponseEntity.ok(storedName);
    }
}
```

## Explanation

The fix addresses the core gap: `Files.probeContentType()` is not a content inspector on JDK 9+; it is an extension-to-MIME lookup applied to the file's name. By preserving the client's extension on the temp file, the code bypassed its own validation entirely.

**Changes made:**

1. **Remove extension preservation** (line 38, original): Create temp file with a neutral `.tmp` suffix, so probeContentType cannot key off a client-supplied extension.
2. **Replace with Tika** (line 42, now): Use `tika.detect(path)` to inspect actual file bytes. Tika decodes headers and file signatures, not names.
3. **Add MIME-to-extension map** (lines 23–27): Allowlist-driven mapping ensures only validated types produce extensions, and the extension comes from server-controlled data, not the request.
4. **Store with validated extension** (line 59): Filename now includes both the UUID (prevents traversal) and the server-mapped extension (prevents the attacker from controlling how the file is served).

The allowlist-matched type flows to the extension lookup, not the original request value. If Tika detects a type not in the map, the upload is rejected.

## Behaviour changes

- **Detection is now content-based**: An executable uploaded with a `.jpg` extension is detected by its actual signature and rejected.
- **Extension is server-controlled**: The stored filename's extension derives from the server's MIME map, not the upload request.
- **Storage includes extension**: The UUID alone is insufficient to determine how a file is served; the validated extension is now retained for correct `Content-Type` headers on download.
- **New dependency**: Tika must be added to the build (Maven/Gradle). Version constraint: any version from the Tika 2.x line is acceptable; pin to your organization's standard or consult advisory data for the latest version before merging.
- **Performance**: Tika inspection adds a small latency per upload (milliseconds for typical files) and requires additional JVM heap for MIME type detection; this is the expected cost of content-based validation.
