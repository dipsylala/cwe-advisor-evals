## Verdict

exploitable (confidence: high)

CWE-434 (Unrestricted Upload of File with Dangerous Type), Java / Spring.

## Source

- **Source**: `@RequestParam("file") MultipartFile file` on the `/upload` `@PostMapping` handler - `file.getOriginalFilename()`, an HTTP request value fully controlled by the client.
- **Data flow**: `originalFilename` is concatenated directly onto the fixed prefix `UPLOAD_DIR = "/var/www/html/uploads/"` to build `destination` (`new File(...)`), with no check on file type, content, or filename.
- **Sink**: `file.transferTo(destination)` (line 21) writes the uploaded bytes to that path. `UPLOAD_DIR` sits under `/var/www/html/`, a conventional web-served document root, so any extension the client chooses (`.jsp`, `.php`, `.html` with script) can be dropped there and potentially served or executed by the front-end web server. The client-controlled filename also carries no path-traversal or extension check.
- **Sink contract** (original): `transferTo` returns `void` and throws `IOException` on failure, which the handler declares and does not otherwise handle; the caller discards nothing meaningful but relies entirely on the caller-supplied path being safe, which it is not. The handler then echoes `destination.getAbsolutePath()` back to the client, which is itself an unnecessary disclosure of the server-side storage path built from client input.

No validation exists between source and sink, so the path is live: verdict is `exploitable`.

## Fix

**Library recommendation**: Apache Tika (`org.apache.tika:tika-core`) for content-based type detection. The loaded guidance gives no minimum safe version - do not source one from recall; resolve the version to add in `pom.xml`/`build.gradle` against current SCA/dependency-check tooling before merging.

**Vulnerable code** (original, lines 17-23):

```java
public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
    String originalFilename = file.getOriginalFilename();
    File destination = new File(UPLOAD_DIR + originalFilename);
    // SAST FINDING: CWE-434 reported here. Sink is the next statement.
    file.transferTo(destination);
    return "Uploaded to " + destination.getAbsolutePath();
}
```

**Fixed code**:

```java
package evalcases;

import org.apache.tika.Tika;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Map;
import java.util.UUID;

@RestController
public class MultipartUploadNoValidation {

    // Outside any directory the web server serves directly - not the original /var/www/html/uploads/ webroot path.
    private static final Path UPLOAD_DIR = Paths.get("/var/app-storage/uploads/");

    // Allowlist of business-required types, mapped to the extension used for storage.
    // Extend only with types the endpoint actually needs to accept.
    private static final Map<String, String> ALLOWED_TYPES = Map.of(
            "image/png", ".png",
            "image/jpeg", ".jpg"
    );

    private static final Tika TIKA = new Tika();

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
        byte[] content = file.getBytes();

        // Detect the real type from content, not from the client-supplied filename or Content-Type header.
        String detectedType = TIKA.detect(content);
        String extension = ALLOWED_TYPES.get(detectedType);
        if (extension == null) {
            throw new IllegalArgumentException("Unsupported file type");
        }

        // A signature match only proves the prefix is valid; re-encoding discards anything appended
        // after the image's structural end (e.g. a payload tacked on after a PNG's IEND chunk).
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(content));
        if (image == null) {
            throw new IllegalArgumentException("Unsupported or corrupt image");
        }

        // Generated name, not the client's filename - removes both path-traversal and
        // dangerous-extension control from the request.
        String storedFilename = UUID.randomUUID() + extension;
        Path destination = UPLOAD_DIR.resolve(storedFilename);
        String formatName = extension.equals(".png") ? "png" : "jpg";

        try (var out = Files.newOutputStream(destination, StandardOpenOption.CREATE_NEW)) {
            ImageIO.write(image, formatName, out);
        }

        return "Uploaded as " + storedFilename;
    }
}
```

## Explanation

The original handler trusted the client-supplied filename both as the storage path and as the implicit file-type decision, and wrote into a directory conventionally served by the front-end web server - so an attacker could upload a script with an executable extension and have it run server-side. The fix breaks taint at two points: the stored path is built entirely from a server-generated `UUID`, never from `getOriginalFilename()`, which also closes the path-traversal angle the original left open; and the file type is decided by inspecting the actual bytes with Tika against a fixed allowlist, with the stored extension taken from that allowlist rather than from the client. Because a signature match only verifies the leading bytes, the image is additionally decoded and re-encoded with `ImageIO` before being persisted, which discards any payload appended past the image's structural end - a check alone would not catch that. Storage also moves outside the web-served `/var/www/html` tree, so even a future validation gap could not result in the web server directly executing an uploaded file. The Tika dependency addresses detection; the allowlist, generated filename, re-encode, and storage-location change are all code-level and remain necessary regardless of library version.

Confidence: high. Assumption: the endpoint's actual business requirement was not stated, so the allowlist was scoped to PNG/JPEG images as the most common concrete case the guidance illustrates (Tika detection plus ImageIO re-encoding); a real deployment should replace this with whatever file types the feature genuinely needs, following the same detect-allowlist-and-re-encode/derive-extension pattern for each.

## Behaviour changes

- **Accepted file types narrowed**: the original accepted any file; the fix rejects (via `IllegalArgumentException`) anything that isn't detected as PNG or JPEG content. Required to close the weakness - the allowlist should be widened to the endpoint's real business-required types, not to "any file."
- **Storage location changed**: from `/var/www/html/uploads/` (a web-served path) to `/var/app-storage/uploads/` (outside the web server's document root). Required so that even a future gap in type validation cannot lead to the web server executing an uploaded file directly; the new path is a placeholder for whatever non-served storage location the deployment actually uses.
- **Storage filename changed**: from the client-supplied `originalFilename` to a generated `UUID` plus an allowlist-derived extension. Required to remove both path-traversal control and dangerous-extension control from the request.
- **File content changed on disk**: the original bytes are decoded and re-encoded through `ImageIO` rather than copied verbatim via `transferTo`. Required to strip any data appended after the image's structural end that a signature check alone would not catch; this also means the stored bytes are not byte-identical to the upload even for a legitimate image (e.g. metadata may be dropped, compression may be re-applied).
- **Response body changed**: returns `"Uploaded as " + storedFilename` (the generated name) instead of `"Uploaded to " + destination.getAbsolutePath()`. Required because the absolute server-side path is no longer meaningful to the caller and echoing it back is an unnecessary information disclosure; this also necessarily follows from the filename no longer being client-supplied.
- **Memory usage increased**: the fix reads the full upload into memory (`file.getBytes()`) to sniff content and re-encode it, where the original streamed directly to disk via `transferTo`. This is required for content-based validation, but makes the endpoint more sensitive to upload size - per the loaded guidance, `spring.servlet.multipart.max-file-size` and `max-request-size` should be set explicitly (not left at the Spring Boot defaults) as a complementary control; that configuration change is outside this source file and is not made here.
- **New dependency**: `org.apache.tika:tika-core` is required and must be added to the build manifest with a version resolved via SCA/dependency-check tooling, not supplied here.
