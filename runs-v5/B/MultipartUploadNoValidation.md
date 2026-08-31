## Verdict

**exploitable** (confidence: high)

- CWE-434 (Unrestricted Upload of File with Dangerous Type)
- Location: `MultipartUploadNoValidation.java`, `handleUpload()`, line 21 (`file.transferTo(destination)`)

## Source

`@RequestParam("file") MultipartFile file` on the `/upload` `@PostMapping` handler (line 17). `file.getOriginalFilename()` (line 18) is a client-supplied HTTP request value with no server-side verification.

## Fix

**Library recommendation**: Apache Tika (`org.apache.tika:tika-core`) for content-based type detection. The loaded guidance gives no minimum safe version for this library, so no version is supplied here - resolve and pin the version through SCA/dependency-check tooling before merging, and add the dependency to the project's `pom.xml`/`build.gradle` (not shown in the case file, so not edited here).

**Vulnerable code:**

```java
private static final String UPLOAD_DIR = "/var/www/html/uploads/";

@PostMapping("/upload")
public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
    String originalFilename = file.getOriginalFilename();
    File destination = new File(UPLOAD_DIR + originalFilename);
    // No type validation, filename is client-controlled, storage is inside the served webroot
    file.transferTo(destination);
    return "Uploaded to " + destination.getAbsolutePath();
}
```

**Fixed code:**

```java
package evalcases;

import org.apache.tika.Tika;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@RestController
public class MultipartUploadNoValidation {

    // Outside the web-served /var/www/html tree so an uploaded file can never be executed or served directly
    private static final String UPLOAD_DIR = "/var/data/uploads/";

    private static final Set<String> ALLOWED_TYPES = Set.of("image/png", "image/jpeg", "application/pdf");

    private static final Map<String, String> TYPE_TO_EXT = Map.of(
            "image/png", ".png",
            "image/jpeg", ".jpg",
            "application/pdf", ".pdf");

    private static final Tika TIKA = new Tika();

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        byte[] content = file.getBytes();
        String detectedType = TIKA.detect(content);

        if (!ALLOWED_TYPES.contains(detectedType)) {
            throw new IllegalArgumentException("Unsupported file type: " + detectedType);
        }

        String extension = TYPE_TO_EXT.get(detectedType);
        String storedFilename = UUID.randomUUID() + extension;
        File destination = new File(UPLOAD_DIR + storedFilename);

        file.transferTo(destination);
        return "Uploaded to " + destination.getAbsolutePath();
    }
}
```

## Explanation

The handler trusted `getOriginalFilename()` - a client-supplied, unverified value - both to decide the file's type and to build its storage path, and wrote the result directly into `/var/www/html/uploads/`, a path the server serves. An attacker could upload a web shell (e.g. `shell.jsp`) and have it served and executed immediately, with no type check of any kind in the way. The fix reads the uploaded bytes and detects the real content type with Apache Tika (`tika.detect(bytes)`), rejecting anything not on a fixed allowlist of business-required types, so a mismatched extension/content pair or an executable disguised as an image is stopped before it is written. The storage filename is now a generated `UUID` with an extension taken from a fixed `type -> extension` map keyed off the Tika-detected type, so the client no longer controls either the storage path or the extension the file will later be served under - this also closes the path-traversal opening that concatenating the raw filename left in the original code. The storage directory itself moves to `/var/data/uploads/`, outside the tree the web server exposes, so even a file that slipped past validation could not be reached or executed by a direct request. `transferTo()` remains the sink and keeps its original throws/return contract (`void`, `IOException` on failure).

## Behaviour changes

- **Rejects previously-accepted uploads**: any file whose detected content type is not `image/png`, `image/jpeg`, or `application/pdf` now throws `IllegalArgumentException` instead of being stored. This is the intended effect of the fix (closing the unrestricted-upload weakness); the three-type allowlist is a stand-in for the actual business requirement and should be adjusted to match the real set of file types the endpoint needs to accept.
- **Storage location changed**: files now land in `/var/data/uploads/` instead of `/var/www/html/uploads/`. Required to take the stored file out of the server's directly-served webroot; any code elsewhere that serves these files back by reading from the old webroot path will need to be updated to read from the new location (none exists in the provided file).
- **Storage filename changed**: the stored file is now named `<UUID>.<detected-extension>` instead of the client's original filename. Required to remove client control over both the storage path (traversal) and the served extension (dangerous type); the response message still returns `destination.getAbsolutePath()` as before, so callers relying on that response shape are unaffected, only the path value itself differs.
- **New read of the file body**: `file.getBytes()` is called to obtain bytes for Tika to inspect, which the original code never did. Standard `MultipartFile` implementations buffer to memory or a temp file, so this and the subsequent `transferTo()` call are independent and both succeed; for very large uploads this adds a full in-memory read, so pairing this fix with `spring.servlet.multipart.max-file-size` / `max-request-size` limits (recommended by the loaded guidance) is advised, though that configuration is outside the file provided in this case and was not added here.
