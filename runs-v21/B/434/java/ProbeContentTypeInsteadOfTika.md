## Verdict

The finding is confirmed and exploitable. The vulnerability exists because `Files.probeContentType()` on JDK 9+ inspects only the filename (extension), not the actual file bytes, allowing an attacker to bypass content-type validation by uploading a malicious file with a spoofed extension (e.g., `malware.jpg` containing executable code).

## Source

`MultipartFile.getOriginalFilename()` is client-supplied and untrusted. The code extracts the file extension (line 35-37) and creates a temp file with that extension (line 38), then calls `file.transferTo(tempFile)` (line 39) to write the uploaded bytes. The taint source is the client-provided filename suffix; the flow routes through the temp file's path.

## Fix

Replace `Files.probeContentType()` with Apache Tika's byte-based detection via `tika.detect(fileBytes)`. Additionally, avoid using the client's extension on the temp file; use a neutral extension like `.tmp` instead. For images, re-encode using `ImageIO` to strip embedded scripts and malicious metadata. Derive the stored filename extension from the Tika-detected type using an allowlist map, and store with the generated name, not the client-supplied one.

### File: DocumentUploadController.java

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
    private static final Set<String> IMAGE_TYPES = Set.of("image/jpeg", "image/png");
    private static final Map<String, String> MIME_TO_EXT = Map.of(
            "image/jpeg", ".jpg",
            "image/png", ".png",
            "application/pdf", ".pdf"
    );
    private static final Path UPLOAD_DIR = Paths.get("/var/app/uploads");
    private static final Tika tika = new Tika();

    @PostMapping("/api/documents")
    public ResponseEntity<String> uploadDocument(@RequestParam("file") MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("Empty file");
        }

        // Write the upload to a temp file for content inspection
        Path tempFile = Files.createTempFile("upload-", ".tmp");
        try {
            file.transferTo(tempFile);

            // Detect the actual file type from bytes using Tika, not the filename
            byte[] fileBytes = Files.readAllBytes(tempFile);
            String detectedType = tika.detect(fileBytes);

            if (detectedType == null || !ALLOWED_TYPES.contains(detectedType)) {
                return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                        .body("Rejected: unrecognized or disallowed file type (" + detectedType + ")");
            }

            // For images, re-encode to strip embedded scripts or malicious metadata
            Path processedFile = tempFile;
            if (IMAGE_TYPES.contains(detectedType)) {
                BufferedImage image = ImageIO.read(tempFile.toFile());
                if (image == null) {
                    return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                            .body("Rejected: invalid image file");
                }
                Path reencoded = Files.createTempFile("reenc-", ".tmp");
                String formatName = getFormatName(detectedType);
                ImageIO.write(image, formatName, reencoded.toFile());
                Files.deleteIfExists(tempFile);
                processedFile = reencoded;
            }

            // Generate storage name with extension from the detected type
            String extension = MIME_TO_EXT.get(detectedType);
            String storedName = UUID.randomUUID().toString() + extension;
            Path destination = UPLOAD_DIR.resolve(storedName);

            // Move the processed file to the final destination
            Files.move(processedFile, destination, StandardCopyOption.REPLACE_EXISTING);

            return ResponseEntity.ok(storedName);
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }

    private String getFormatName(String mimeType) {
        if ("image/jpeg".equals(mimeType)) {
            return "jpg";
        } else if ("image/png".equals(mimeType)) {
            return "png";
        }
        return "png";
    }
}
```

## Explanation

The original code relied on `Files.probeContentType()` to validate the uploaded file's type. On JDK 9+, this method inspects only the filename's extension, not the actual file bytes. Because the temp file was created with the client's original filename suffix (line 35-37 in the original), an attacker could upload a malicious executable renamed as `malware.jpg` and pass validation.

The fixed code:
1. Creates the temp file with a neutral `.tmp` extension (immune to filename-based detection).
2. Reads the file's actual bytes and uses Apache Tika's `tika.detect(fileBytes)` to inspect the content, not the filename.
3. Validates the detected type against the allowlist of allowed MIME types.
4. For image uploads, re-encodes the image using `ImageIO.read()` followed by `ImageIO.write()`, which discards any embedded scripts, polyglot payloads, or malformed metadata that may follow valid image data.
5. Derives the stored filename extension from the Tika-detected type using a hardcoded allowlist map (`MIME_TO_EXT`), ensuring the file's handler is determined by the server, not the attacker.
6. Stores the file with a `UUID`-generated name in the configured `UPLOAD_DIR`, which is outside the web root.

The fix closes the CWE-434 weakness by ensuring the file's content—not its name—determines what file type the server accepts and how it will be handled.

## Behaviour changes

- The temp file's extension no longer reflects the client's input, eliminating the filename-keyed detection bypass.
- Image uploads are re-encoded, which may introduce a slight performance cost for image processing but removes polyglot and embedded-payload risks.
- Files are now named solely by server-generated UUIDs with extensions derived from detected content, preventing both traversal and extension-spoofing attacks.
- The endpoint will reject image files that do not decode (e.g., corrupted or syntactically invalid images), returning a 415 Unsupported Media Type error. This is a strengthened validation; previously such files might have been accepted if the extension matched.
- All other behavior—allowlist validation, storage location, response format—remains unchanged.
