## Verdict

The vulnerability is **confirmed and fixable**. The code relies on `Files.probeContentType()` to validate uploaded file types, but this method is unreliable on JDK 9+: it examines filename extension rather than actual file bytes. Since the temp file is created with the client-supplied extension (line 38), an attacker can rename a malicious executable to `.jpg` and bypass content-type validation entirely.

## Source

- **Attacker-controlled input:** `MultipartFile file` parameter, specifically its bytes and original filename
- **Taint entry point:** Line 25, the `uploadDocument` method parameter
- **Propagation:** Line 34-39 extracts the client-supplied filename suffix and creates a temp file with that suffix; line 42 passes this temp file to `Files.probeContentType()`

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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@RestController
public class DocumentUploadController {

    private static final Set<String> ALLOWED_TYPES = Set.of("image/jpeg", "image/png", "application/pdf");
    private static final Path UPLOAD_DIR = Paths.get("/var/app/uploads");
    private static final Map<String, String> MIME_TO_EXT = Map.of(
            "image/jpeg", ".jpg",
            "image/png", ".png",
            "application/pdf", ".pdf"
    );

    @PostMapping("/api/documents")
    public ResponseEntity<String> uploadDocument(@RequestParam("file") MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("Empty file");
        }

        // Detect the actual content type from file bytes using Tika,
        // not from the client-supplied filename extension.
        byte[] fileBytes = file.getBytes();
        Tika tika = new Tika();
        String detectedType = tika.detect(fileBytes);

        if (detectedType == null || !ALLOWED_TYPES.contains(detectedType)) {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                    .body("Rejected: unrecognized or disallowed file type (" + detectedType + ")");
        }

        // Store file with server-generated name and extension derived from the
        // Tika-detected type, not the client-supplied filename.
        String storedName = UUID.randomUUID().toString() + MIME_TO_EXT.get(detectedType);
        Path destination = UPLOAD_DIR.resolve(storedName);
        Files.write(destination, fileBytes, StandardOpenOption.CREATE_NEW);

        return ResponseEntity.ok(storedName);
    }
}
```

## Explanation

**What changed:** Replaced `Files.probeContentType()` with Apache Tika's `tika.detect(fileBytes)`, removed temp file creation, added a MIME-to-extension mapping, and now derive the stored filename's extension from the Tika-detected type rather than the client-supplied extension.

**Why it closes the weakness:** 

On JDK 9+, `Files.probeContentType()` delegates to platform-specific MIME-type detectors that examine filename extension, not file content. By passing a temp file with the client-controlled suffix, the original code allowed an attacker to bypass validation: rename a `.exe` to `.jpg` and `probeContentType()` returns `image/jpeg` based solely on the extension.

Tika inspects actual file bytes to determine MIME type, making extension-based spoofing impossible. The fix breaks taint after validation by deriving the stored file's extension from the Tika-detected type via an allowlist map (`MIME_TO_EXT`), so the server controls both the name and extension of persisted files. Using `StandardOpenOption.CREATE_NEW` prevents overwrite attacks.

## Behaviour changes

- **Added dependency:** Requires Apache Tika (`org.apache.tika:tika-core`) on the classpath
- **Removed temp file:** No longer creates an intermediate temp file, improving efficiency
- **Changed detection method:** Calls `tika.detect(fileBytes)` (content-based) instead of `Files.probeContentType(tempFile)` (extension-based)
- **Added stored extension:** Files are now stored with server-controlled extensions mapped from detected type (e.g., `550e8400-e29b-41d4-a716-446655440000.jpg`), making MIME type unambiguous when files are later served
- **Changed write strategy:** Uses `Files.write()` with `StandardOpenOption.CREATE_NEW` instead of `transferTo()`, preventing accidental overwrites of existing files
