## Verdict

exploitable

- cwe_id: CWE-434 (Unrestricted Upload of File with Dangerous Type)
- location: `ImageUploadController.java`, line 45 (`Files.copy(file.getInputStream(), destination, ...)`)
- confidence: high

## Source

`MultipartFile file` bound via `@RequestParam("file")` on `POST /api/images` (`ImageUploadController.uploadImage`). The only gate before the file is written is `file.getContentType()` checked against `ALLOWED_CONTENT_TYPES` (`image/png`, `image/jpeg`). `getContentType()` returns the client-supplied `Content-Type` part of the multipart request - it is an HTTP header value the caller sets, not a property the server derives from the file's bytes. An attacker can send any payload (a JSP/JSPX web shell, an HTML file, a script) with the multipart part's `Content-Type` header forged to `image/png` or `image/jpeg` and pass this check unconditionally.

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

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
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

    private static final Map<String, String> IMAGEIO_FORMAT_BY_CONTENT_TYPE = Map.of(
            "image/png", "png",
            "image/jpeg", "jpg"
    );

    private static final Path UPLOAD_DIR = Paths.get("/var/data/uploads/images");

    private final Tika tika = new Tika();

    @PostMapping("/api/images")
    public ResponseEntity<String> uploadImage(@RequestParam("file") MultipartFile file) throws IOException {
        byte[] content = file.getBytes();

        // Detect the real file type from its bytes; the client-supplied
        // Content-Type header is not trustworthy on its own.
        String detectedType = tika.detect(content);
        if (!ALLOWED_CONTENT_TYPES.contains(detectedType)) {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Unsupported image type");
        }

        // Re-encode the image so any bytes beyond the pixel data - such as a
        // payload appended after a valid signature, or active content embedded
        // in metadata - are discarded rather than persisted.
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(content));
        if (image == null) {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Unsupported image type");
        }
        ByteArrayOutputStream reencoded = new ByteArrayOutputStream();
        boolean written = ImageIO.write(image, IMAGEIO_FORMAT_BY_CONTENT_TYPE.get(detectedType), reencoded);
        if (!written) {
            return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("Unsupported image type");
        }

        // Filename generation is already safe: a random UUID with the extension
        // looked up from a fixed map keyed by the Tika-detected content type.
        String extension = EXTENSION_BY_CONTENT_TYPE.get(detectedType);
        String storedName = UUID.randomUUID() + extension;
        Path destination = UPLOAD_DIR.resolve(storedName);

        Files.copy(new ByteArrayInputStream(reencoded.toByteArray()), destination, StandardCopyOption.REPLACE_EXISTING);

        return ResponseEntity.ok(storedName);
    }
}
```

**library_recommendation**: Apache Tika (`org.apache.tika:tika-core`), already used via `Tika.detect(byte[])`. The knowledge base entry names no minimum safe version; confirm the resolved version against SCA/dependency-check tooling before merging. This project has no `pom.xml`/`build.gradle` in the case's call chain, so the manifest change to add `org.apache.tika:tika-core` as a dependency is not shown here - add it to whatever build file the real project uses.

## Explanation

The vulnerable code validated only `MultipartFile.getContentType()`, a client-controlled HTTP header, so any file could pass as `image/png`/`image/jpeg` regardless of its actual content. The fix reads the file into memory once (`file.getBytes()`) and uses Apache Tika's magic-byte detector (`Tika.detect(byte[])`) to determine the file's real type from its content, checking that result against the same allowlist. Passing the content-sniffing check alone is not sufficient, because a signature check only inspects a prefix and a polyglot file can carry a valid image header followed by an arbitrary payload; the fix therefore also decodes the image with `ImageIO.read()` and re-encodes it with `ImageIO.write()` before persisting, which discards any bytes that are not actual pixel data (including trailing payloads and most embedded active metadata). The stored extension continues to come from the fixed `EXTENSION_BY_CONTENT_TYPE` map, now keyed by the Tika-detected type rather than the client-supplied header, so the allowlist-matched value - not client input - drives what gets appended to the generated filename. If `ImageIO` cannot decode the detected type (a valid PNG signature followed by non-image bytes that Tika's prefix sniff still matched, for example), `ImageIO.read()` returns `null` and the request is rejected rather than silently persisting unverified bytes.

## Behaviour changes

- **Content-Type header no longer read for validation** - `file.getContentType()` is not called at all; validation now runs entirely against detected bytes. Reason: closes the weakness; the header was never trustworthy.
- **File is now fully buffered in memory** (`file.getBytes()`, then two `ByteArrayInputStream`/`ByteArrayOutputStream` passes) instead of being streamed directly from `file.getInputStream()` to `Files.copy()`. Reason: both content-sniffing and re-encoding require the complete byte content; this is unavoidable given the fix but increases per-request memory use. The knowledge base guidance separately recommends enforcing `spring.servlet.multipart.max-file-size`/`max-request-size`, which bounds this - that setting lives in `application.properties`, outside this file's call chain, and is not part of the file's diff.
- **Bytes on disk after a successful upload are the re-encoded output of `ImageIO.write()`, not the client's original bytes.** Reason: this is the mechanism that removes any payload appended after the image's pixel data or embedded in metadata; it can also normalize incidental encoder details (e.g. compression parameters) of an otherwise-legitimate image, which is an accepted trade-off of re-encoding as a defence.
- **A file that is valid per magic bytes but not decodable by `ImageIO`** (e.g., a format variant `ImageIO` doesn't support, or a truncated file) is now rejected with `415 Unsupported Media Type` where the original would have rejected only on Content-Type mismatch. Reason: the original had no equivalent check; this is a stricter but intentional consequence of verifying decodability, not a change to any previously-relied-on success path in this handler.
- No change to the success response body, the generated filename format, the storage directory, or the `REPLACE_EXISTING` copy option.

## Verification

Compiled the fixed file with `javac` against real dependency jars resolved from the local Maven repository (`org.springframework:spring-web:5.3.39`, `spring-core`, `spring-beans`, `spring-context`, `spring-webmvc:5.3.39`, `javax.servlet:javax.servlet-api:4.0.1`, `org.apache.tika:tika-core:2.9.2`) - the same versions already resolved elsewhere in this environment. Compilation succeeded with zero errors or warnings, confirming every Spring and Tika API used (`Tika.detect(byte[])`, `MultipartFile.getBytes()`, `ResponseEntity`/`HttpStatus`, `ImageIO.read`/`ImageIO.write`) exists with the signature used and that the file is otherwise syntactically and type-correct. `javax.imageio.ImageIO`, `java.awt.image.BufferedImage`, `java.io.ByteArrayInputStream`/`ByteArrayOutputStream` are JDK standard library and compiled as part of the same pass (JDK 26 `javac`).

## Assumptions

- No `pom.xml`/`build.gradle` was in the case's call chain, so the Tika dependency addition is stated as guidance rather than shown as a manifest diff.
- Assumed PNG/JPEG re-encoding via `ImageIO` is acceptable for this endpoint's use case (i.e., pixel-identical preservation is not a requirement) - this is the language guidance's stated pattern for image uploads and is the only way to close the polyglot gap that a magic-byte check alone leaves open.
