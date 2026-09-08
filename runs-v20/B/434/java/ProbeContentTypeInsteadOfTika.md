## Verdict

Exploitable. Confidence: high.

## Source

`MultipartFile file` bound from the `@RequestParam("file")` parameter of `uploadDocument()` (`DocumentUploadController.java:25`) - both the uploaded bytes and `file.getOriginalFilename()` are client-controlled.

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
        String originalFilename = file.getOriginalFilename();
        String suffix = (originalFilename != null && originalFilename.contains("."))
                ? originalFilename.substring(originalFilename.lastIndexOf('.'))
                : ".tmp";
        Path tempFile = Files.createTempFile("upload-", suffix);
        file.transferTo(tempFile);

        // Detect the real type from the file's bytes with Apache Tika. Files.probeContentType()
        // is not a content check on JDK 9+: its built-in detectors key off the file name
        // (extension-to-MIME lookup), so against a name whose suffix the client chose, it
        // validates nothing - any content saved with an allowed extension passes. Tika.detect(byte[])
        // sniffs the actual magic bytes and ignores the file name entirely.
        byte[] fileBytes = Files.readAllBytes(tempFile);
        String detectedType = TIKA.detect(fileBytes);

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

**Library recommendation**: `org.apache.tika:tika-core` (Maven Central). No manifest file is part of this call chain, so no `pom.xml`/`build.gradle` change is shown here; add the dependency to the project's build file and confirm the resolved version through SCA/dependency-check tooling before merging - no minimum version is asserted from recall.

## Explanation

The handler saves the upload to a temp file whose suffix is taken verbatim from the client-supplied `getOriginalFilename()`, then calls `Files.probeContentType(tempFile)` and checks the result against an allowlist. On JDK 9+, the JDK's built-in `probeContentType` detectors (both the Linux and Windows defaults) resolve the MIME type from the file name's extension, not from the file's bytes - the libmagic-backed content sniffer that shipped on JDK 8 and earlier was removed in JDK 9. Because the extension the temp file carries is the one the client chose, an attacker can upload a file containing arbitrary bytes - a web shell, an HTML document with an embedded script, an executable - named with an allowed extension such as `.jpg`, and `probeContentType` will report `image/jpeg` regardless of what the file actually contains, so it passes `ALLOWED_TYPES.contains(...)` and is stored. The fix replaces the sink with Apache Tika's `Tika.detect(byte[])`, which classifies the file from its magic bytes read off disk (`Files.readAllBytes(tempFile)`) and never consults the file name, so the allowlist check is now validating what was actually uploaded rather than what the client claims it is. The already-correct parts of the handler - generating a random UUID for the stored filename and writing outside the webroot to `/var/app/uploads` - are left as they were; the weakness here is specific to the content-type detection sink, not the storage path.

## Behaviour changes

- `detectedType` is now computed from the uploaded file's byte content instead of its (client-controlled) file name/extension. This is the intended effect of the fix, not a side effect: it is stricter, not looser - files that were previously accepted purely because of a matching extension and are not actually `image/jpeg`, `image/png`, or `application/pdf` will now be correctly rejected with `HTTP 415`. Files whose extension and true content already agreed continue to be accepted exactly as before.
- No change to control flow, the allowlist itself, the error path, the stored filename generation, or the storage location. `detectedType` continues to be the value used in the rejection message and the allowlist check (no other downstream use), so no tainted value is reintroduced after validation.
- Added dependency: `org.apache.tika:tika-core`, and one new field (`TIKA`) and import (`org.apache.tika.Tika`). No existing symbol's signature, return type, or arguments changed.

## Verification

Compiled the fixed file with `javac` against local stub classes reproducing the exact signatures of every external symbol used (`org.springframework.http.HttpStatus`, `ResponseEntity`/`ResponseEntity.BodyBuilder`, the `@PostMapping`/`@RequestParam`/`@RestController` annotations, `MultipartFile`, and `org.apache.tika.Tika` with `Tika()` and `detect(byte[])`) - the real Spring/Tika jars are not resolvable in this environment, so this checks syntax and call-signature correctness rather than linking against the real libraries. Compilation succeeded with no errors or warnings. `Files.readAllBytes(Path)` and the retained `Files`/`Paths`/`UUID` calls are unchanged standard-library usages already present in, or directly analogous to, the original file.
