## Verdict
VULNERABLE

## Source
Client-supplied file on line 25, transferred to disk on line 39.

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
import java.nio.file.StandardCopyOption;
import java.util.Set;
import java.util.UUID;

@RestController
public class DocumentUploadController {

    private static final Set<String> ALLOWED_TYPES = Set.of("image/jpeg", "image/png", "application/pdf");
    private static final Path UPLOAD_DIR = Paths.get("/var/app/uploads");

    @PostMapping("/api/documents")
    public ResponseEntity<String> uploadDocument(@RequestParam("file") MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("Empty file");
        }

        // Write the upload to a temp file so we can inspect the real content
        // type on disk rather than trusting the client-supplied header.
        // Preserve the client's extension on the temp file so probeContentType
        // has something to key off.
        String originalFilename = file.getOriginalFilename();
        String suffix = (originalFilename != null && originalFilename.contains("."))
                ? originalFilename.substring(originalFilename.lastIndexOf('.'))
                : ".tmp";
        Path tempFile = Files.createTempFile("upload-", suffix);
        file.transferTo(tempFile);

        // Use Tika to detect the actual file content type by examining the file bytes,
        // not just the filename extension.
        Tika tika = new Tika();
        String detectedType = tika.detect(tempFile.toFile());

        if (detectedType == null || !ALLOWED_TYPES.contains(detectedType)) {
            Files.deleteIfExists(tempFile);
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                    .body("Rejected: unrecognized or disallowed file type (" + detectedType + ")");
        }

        String storedName = UUID.randomUUID().toString();
        Path destination = UPLOAD_DIR.resolve(storedName);
        Files.move(tempFile, destination, StandardCopyOption.REPLACE_EXISTING);

        return ResponseEntity.ok(storedName);
    }
}
```

## Explanation

`Files.probeContentType()` inspects only the filename extension and uses FileTypeDetector SPI; it never reads file content. An attacker uploads a file with extension `.pdf` but binary content of an executable, and the check on line 44 passes because `probeContentType()` returns `"application/pdf"` based solely on the extension.

Apache Tika reads the file's magic bytes to determine its actual type. Replace the `Files.probeContentType()` call with `new Tika().detect(tempFile.toFile())` to inspect the real content. Add `import org.apache.tika.Tika;` and ensure `tika-core` is a compile-time dependency in the build (typically already present in Spring Boot projects via transitive dependency on other libraries, but should be explicit in pom.xml or gradle).
