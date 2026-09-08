## Verdict

The vulnerability is confirmed. The code validates the uploaded file's content type against an allowlist, but trusts the client-supplied `Content-Type` HTTP header rather than inspecting the file's actual bytes. An attacker can upload a malicious executable (e.g., a script or binary) and set the `Content-Type` header to `image/jpeg` to bypass the validation and store the file under an image extension.

## Source

**File:** `ImageUploadController.java`  
**Line:** 33-45 (vulnerability in the absence of content validation)

The source is the `MultipartFile file` parameter, whose `getContentType()` method returns a client-supplied HTTP header value. The sink is line 45, where `Files.copy()` writes the unvalidated file to disk.

**Data flow:**
1. Line 33: `String contentType = file.getContentType()` - retrieves the client-supplied header
2. Line 34: Validates `contentType` against `ALLOWED_CONTENT_TYPES` - but this only checks if the header value is in the allowlist, not if the file's actual bytes match that type
3. Line 40-41: Generates filename using the client-validated-but-unverified `contentType`
4. Line 45: Writes the file bytes without verifying they actually match the claimed type

The gap: the validation trusts the client's `Content-Type` header. An attacker uploads a binary executable with `Content-Type: image/jpeg` set in the request, passes the header check, and the binary is stored as `<uuid>.jpg`.

## Fix

### File: ImageUploadController.java

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
import java.nio.file.StandardOpenOption;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@RestController
public class ImageUploadController {

    private static final Set<String> ALLOWED_CONTENT_TYPES = Set.of("image/png", "image/jpeg");

    private static final Map<String, String> EXTENSION_BY_CONTENT_TYPE = Map.of(
            "image/png", ".png",
            "image/jpeg", ".jpg"
    );

    private static final Path UPLOAD_DIR = Paths.get("/var/data/uploads/images");

    @PostMapping("/api/images")
    public ResponseEntity<String> uploadImage(@RequestParam("file") MultipartFile file) throws IOException {
        // Read file bytes for content detection
        byte[] fileBytes = file.getBytes();

        // Detect actual content type from file bytes using Tika
        Tika tika = new Tika();
        String detectedContentType = tika.detect(fileBytes);

        // Validate detected content type against allowlist
        if (detectedContentType == null || !ALLOWED_CONTENT_TYPES.contains(detectedContentType)) {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Unsupported image type");
        }

        // Derive extension from detected content type, not from client-supplied source
        String extension = EXTENSION_BY_CONTENT_TYPE.get(detectedContentType);
        String storedName = UUID.randomUUID() + extension;
        Path destination = UPLOAD_DIR.resolve(storedName);

        // Write file bytes to destination
        Files.write(destination, fileBytes, StandardOpenOption.CREATE_NEW);

        return ResponseEntity.ok(storedName);
    }
}
```

## Explanation

The fix adds magic byte detection using Apache Tika (`org.apache.tika:tika-core`). The file bytes are read into memory, and `Tika.detect(byte[])` inspects the actual file signature (magic bytes) to determine the true content type, bypassing any client-supplied claim. This detected type is then validated against the allowlist, replacing the trust-the-header approach. Critically, the detected type (not the client-supplied one) is used to derive the stored filename's extension, breaking the taint chain after validation. The file is written with `StandardOpenOption.CREATE_NEW`, which fails atomically if a collision occurs (extremely unlikely with UUID) rather than silently overwriting.

**What changed:**
- Added `import org.apache.tika.Tika`
- Added `import java.nio.file.StandardOpenOption`
- Replaced `String contentType = file.getContentType()` with `byte[] fileBytes = file.getBytes()` and `Tika tika = new Tika(); String detectedContentType = tika.detect(fileBytes)`
- Replaced validation of the client-supplied header with validation of the Tika-detected type
- Changed `Files.copy(file.getInputStream(), destination, StandardCopyOption.REPLACE_EXISTING)` to `Files.write(destination, fileBytes, StandardOpenOption.CREATE_NEW)`

**Why it closes the weakness:** The attacker can no longer forge the Content-Type header to bypass the check. Tika examines the file's byte signature, which cannot be spoofed by modifying HTTP headers. A binary executable uploaded with a forged `image/jpeg` header will be detected as `application/octet-stream` or similar and rejected.

**Dependency requirement:** Apache Tika (`org.apache.tika:tika-core`) must be added to the project's Maven `pom.xml` or Gradle build file. No specific version constraint is required beyond the latest stable release.

## Behaviour changes

- **File validation:** The endpoint now requires the uploaded file's actual bytes to match one of the allowlisted MIME types, not just the HTTP header. Files that claim to be images but contain executable code are rejected.
- **Memory usage:** Files are now loaded into memory (via `file.getBytes()`) for Tika detection before being written to disk. For very large files, this may increase peak memory consumption. If this is a concern, Spring Boot's `spring.servlet.multipart.max-file-size` property should be configured to a reasonable limit (the CWE-434 guidance recommends setting this in `application.properties`).
- **Error handling:** The endpoint continues to return `HttpStatus.UNSUPPORTED_MEDIA_TYPE` on type mismatch, preserving the existing API contract.
- **Atomicity:** File creation now uses `CREATE_NEW`, which fails if the destination already exists, providing stronger guarantees than `REPLACE_EXISTING`.
