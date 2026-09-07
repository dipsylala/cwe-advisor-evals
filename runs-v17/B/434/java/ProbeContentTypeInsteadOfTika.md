## Verdict

The finding is confirmed. Line 42 uses `Files.probeContentType(tempFile)` for type validation, which on JDK 9+ performs extension-based MIME lookup rather than content inspection. The code preserves the client-supplied filename extension in the temp file (lines 34-37), allowing an attacker to upload an executable as `.png` and bypass the allowlist check. The weakness is exploitable because an attacker-controlled file with a forged extension passes validation and is stored to disk.

## Source

The vulnerability arises from two interacting design choices:
1. Lines 34-37 preserve the client-supplied filename extension on the temporary file
2. Line 42 uses `Files.probeContentType()` to validate type, which keys off the filename rather than bytes on JDK 9+

This allows an attacker to upload a malicious executable with a `.png`, `.jpg`, or `.pdf` extension and pass the allowlist check.

## Fix

Replace `Files.probeContentType()` with Apache Tika's byte-level content detection, and remove the client-supplied extension from the temporary file so detection is not influenced by the filename.

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
    private static final Tika TIKA = new Tika();

    @PostMapping("/api/documents")
    public ResponseEntity<String> uploadDocument(@RequestParam("file") MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("Empty file");
        }

        // Write the upload to a temp file without preserving the client-supplied extension,
        // so content detection is based on bytes, not on client-controlled filename.
        Path tempFile = Files.createTempFile("upload-", ".tmp");
        file.transferTo(tempFile);

        // Detect the actual file type from bytes using Tika, not from client-supplied extension.
        byte[] fileBytes = Files.readAllBytes(tempFile);
        String detectedType = TIKA.detect(fileBytes);

        if (detectedType == null || !ALLOWED_TYPES.contains(detectedType)) {
            Files.deleteIfExists(tempFile);
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                    .body("Rejected: unrecognized or disallowed file type (" + detectedType + ")");
        }

        // Derive extension from the Tika-detected type, not from client-supplied filename.
        String extension;
        try {
            MimeTypes mimeTypes = MimeTypes.getDefaultMimeTypes();
            extension = mimeTypes.forName(detectedType).getExtension();
            if (extension == null || extension.isEmpty()) {
                Files.deleteIfExists(tempFile);
                return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                        .body("Rejected: detected type has no known extension");
            }
        } catch (MimeTypeException e) {
            Files.deleteIfExists(tempFile);
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                    .body("Rejected: unrecognized file type");
        }

        String storedName = UUID.randomUUID().toString() + extension;
        Path destination = UPLOAD_DIR.resolve(storedName);
        Files.move(tempFile, destination, StandardCopyOption.REPLACE_EXISTING);

        return ResponseEntity.ok(storedName);
    }
}
```

## Explanation

The fix replaces filename-based type detection with content-based detection using Apache Tika, which inspects the actual file bytes. The key changes:

1. **Temp file naming** (line 38): Changed from `createTempFile("upload-", suffix)` where `suffix` contains the client-supplied extension, to `createTempFile("upload-", ".tmp")`. This ensures `Files.probeContentType()` has no extension to key off if it were still in use.

2. **Content detection** (lines 40-42): Replaced `Files.probeContentType(tempFile)` with `TIKA.detect(fileBytes)`. Tika reads the file's magic bytes (signature) to determine true type, not the filename. This detects when an executable is wrapped in a fake `.png` extension.

3. **Extension derivation** (lines 44-55): Added validation that derives the stored file's extension from Tika's detected type using `MimeTypes.forName(detectedType).getExtension()`. This ensures the extension matches the actual content, not the client's claim.

4. **Stored filename** (line 57): Changed from `UUID.randomUUID().toString()` (no extension) to include the validated extension, so the file is later served with the correct MIME type when retrieved.

The fix breaks the taint chain: after Tika detection and allowlist validation, only the detected type (not the client-supplied value) is used for extension assignment. An attacker cannot forge the MIME type because Tika reads the bytes.

## Behaviour changes

- **Rejected files**: Files whose actual content does not match an allowed type are now rejected, even if they carry an allowed extension. (Previously: passing because extension matched.)
- **Stored filenames**: Files are stored with extensions derived from their detected type rather than their original name. Example: `a1b2c3d4-e5f6.png` instead of `malware.jpg` or a name without extension.
- **Error responses**: Added new error message for types that Tika detects but have no known extension (edge case). Detection failures during Tika inspection are now explicitly rejected rather than stored with null type.
- **Dependency**: Requires Apache Tika (`org.apache.tika:tika-core`) as a new compile-time dependency. Version selection should be determined by SCA tooling and vendor advisories at build time; no specific version is prescribed here.
