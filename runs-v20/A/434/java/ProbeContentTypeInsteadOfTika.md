## Verdict

Confirmed. The type check at line 42 does not verify the file's actual content.

## Source

`file` — the `MultipartFile` bound from the `@RequestParam("file")` upload in `uploadDocument(MultipartFile file)`. Both its bytes and its client-supplied name (`file.getOriginalFilename()`) are attacker-controlled.

## Fix

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

        // Write the upload to a temp file so we can inspect the real content
        // type on disk rather than trusting the client-supplied header.
        // The temp file gets a fixed, extension-less name: content detection
        // below must key off the file's magic bytes, not off any
        // client-supplied extension, so nothing here should hand it one.
        Path tempFile = Files.createTempFile("upload-", null);
        file.transferTo(tempFile);

        // Detect the type from the file's actual content (magic-byte
        // sniffing via Apache Tika), not java.nio.file.Files.probeContentType.
        // probeContentType delegates to a platform FileTypeDetector that on
        // common JVM/OS combinations resolves by file extension rather than
        // by inspecting bytes, so it would simply echo back whatever
        // extension the client's filename carried - an attacker-controlled
        // value - rather than confirming the payload really is an image or
        // PDF.
        String detectedType;
        try {
            detectedType = TIKA.detect(tempFile);
        } catch (IOException e) {
            Files.deleteIfExists(tempFile);
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                    .body("Rejected: unable to determine file type");
        }

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

The original code went out of its way to preserve the client-supplied filename's extension on the temp file "so `probeContentType` has something to key off." That comment describes the vulnerability: `java.nio.file.Files.probeContentType()` delegates to an installed `FileTypeDetector`, and on the common JVM/OS combinations where no custom detector is registered, the default detector resolves the MIME type from the file's name extension (or an OS mechanism such as the Windows registry or `file(1)`'s extension fallback), not from the file's actual bytes. By copying the attacker's original extension onto the probed file, the code hands the detector exactly the value it will trust: an attacker can name a payload `evil.jpg`, and content-type detection reports `image/jpeg` regardless of what bytes are inside, sailing through the `ALLOWED_TYPES` allowlist. This defeats the entire purpose of doing on-disk inspection "rather than trusting the client-supplied header" - the header is not trusted, but the extension effectively still is.

The fix replaces `Files.probeContentType()` with Apache Tika's `Tika.detect(Path)`, which sniffs the file's magic bytes/structure to determine its type independent of any file name or extension. The temp file is now created with `Files.createTempFile("upload-", null)` (no client-derived suffix) so there is no extension left for anything to key off, closing the bypass at its root rather than just swapping the detector while still feeding it attacker-controlled metadata. The rest of the control flow - the allowlist check, deleting the temp file on rejection, and storing accepted files under an extension-less UUID name - is unchanged, since storing without an extension already prevents the upload directory from being used to serve the file as executable content by name.

This requires adding `org.apache.tika:tika-core` as a project dependency (check the current stable release and any open advisories against the version pinned before adopting it).
