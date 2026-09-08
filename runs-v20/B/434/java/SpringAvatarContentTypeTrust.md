## Verdict

CWE-434 (Unrestricted Upload of File with Dangerous Type) - **exploitable**, at `AvatarController.java:20`. Confidence: high.

Library recommendation: add `org.apache.tika:tika-core` for server-side content sniffing. The loaded guidance does not carry a minimum safe version for this library, so none is asserted here - confirm the resolved version with SCA/dependency-check tooling before merging. `javax.imageio` (JDK standard library, no new dependency) is used for the re-encode step.

Assumption: the endpoint's declared allowlist (`image/png`, `image/jpeg`) reflects an actual business requirement to accept only those two avatar types, since the original code encoded that same allowlist; the fix preserves it rather than widening or narrowing it.

## Source

- **Source**: the multipart part bound as `@RequestParam MultipartFile avatar` on `POST /profile/avatar` (`AvatarController.java:19`). Both `avatar.getContentType()` and `avatar.getOriginalFilename()` are client-supplied HTTP request data and are not verified by Spring or the servlet container.
- **Sink (the reported line)**: `AvatarController.java:20` - `avatar.getContentType()` is read and, two lines later, used as the sole gate on what gets accepted (`!"image/png".equals(contentType) && !"image/jpeg".equals(contentType)`). This only inspects a header the client sets; it says nothing about what bytes are actually in the file.
- **Downstream sink**: the same `avatar` object, unchanged, is passed to `storage.store(avatar)` (`AvatarController.java:25`), which resolves the on-disk path from `avatar.getOriginalFilename()` and writes the request body there verbatim via `transferTo()` (`AvatarStorage.java:15-16`).
- **Why this is exploitable as reported**: the two client-supplied values are independent. An attacker can send a request whose `Content-Type` header reads `image/png` (satisfying the line-20 check) while the multipart part's filename is `shell.jsp` and its body is a JSP web shell. The check at line 20 passes, and `AvatarStorage.store()` then writes the file to disk as `shell.jsp`, because nothing in the chain re-derives the extension from the file's real content. The path is live end-to-end; there is no intervening validation of the file bytes or the storage filename. Sink contract of `AvatarStorage.store(MultipartFile)`: **returns** the stored file's simple name (used verbatim as the HTTP response body); **discards** nothing; **implicit arguments** - none, `storageDir` is fixed at construction; **failure behaviour** - propagates `IOException` uncaught, which Spring turns into a 500.

## Fix

### File: AvatarController.java

```java
package cases.upload;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Map;
import java.util.UUID;
import javax.imageio.ImageIO;
import org.apache.tika.Tika;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class AvatarController {
    private static final Tika TIKA = new Tika();
    private static final Map<String, String> ALLOWED_AVATAR_TYPES = Map.of(
            "image/png", "png",
            "image/jpeg", "jpg");

    private final AvatarStorage storage;

    public AvatarController(AvatarStorage storage) {
        this.storage = storage;
    }

    @PostMapping("/profile/avatar")
    public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
        byte[] rawContent = avatar.getBytes();
        String detectedType = TIKA.detect(rawContent);
        String extension = ALLOWED_AVATAR_TYPES.get(detectedType);
        if (extension == null) {
            return ResponseEntity.badRequest().body("unsupported avatar");
        }

        BufferedImage image = ImageIO.read(new ByteArrayInputStream(rawContent));
        if (image == null) {
            return ResponseEntity.badRequest().body("unsupported avatar");
        }

        ByteArrayOutputStream reencoded = new ByteArrayOutputStream();
        ImageIO.write(image, extension, reencoded);

        String storedName = UUID.randomUUID() + "." + extension;
        return ResponseEntity.ok(storage.store(reencoded.toByteArray(), storedName));
    }
}
```

### File: AvatarStorage.java

```java
package cases.upload;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public class AvatarStorage {
    private final Path storageDir;

    public AvatarStorage(Path storageDir) {
        this.storageDir = storageDir;
    }

    public String store(byte[] content, String filename) throws IOException {
        Path target = storageDir.resolve(filename);
        Files.write(target, content, StandardOpenOption.CREATE_NEW);
        return target.getFileName().toString();
    }
}
```

## Explanation

The fix stops trusting the client-supplied `Content-Type` header and replaces it with a server-side check of the actual bytes: Apache Tika sniffs the real MIME type from `avatar.getBytes()` and the result is looked up in a fixed allowlist map that yields both the accept/reject decision and the file extension that will be used for storage, so the extension the client's filename asked for is never consulted. The allowlisted type - not the raw header - is the value that flows downstream. Because a signature check alone only validates the file's prefix (a genuine PNG/JPEG header can still have arbitrary bytes appended after the image data), the accepted bytes are additionally decoded and re-encoded with `ImageIO` before being persisted, which discards anything that isn't actual pixel data for that format. The storage filename is now generated with `UUID.randomUUID()` plus the allowlist-derived extension instead of coming from `getOriginalFilename()`, closing the actual dangerous-type-upload path (an attacker-chosen filename such as `shell.jsp` can no longer reach the filesystem regardless of what `Content-Type` claims). `AvatarStorage.store()` was narrowed to take the re-encoded bytes and the generated name directly, so it can no longer independently re-derive a path from client-controlled input even if called from elsewhere later. Verification: `AvatarStorage.java` was compiled standalone with JDK 26's `javac` and produced no errors; `AvatarController.java` was compiled in the same pass and produced only the expected "package does not exist" errors for `org.springframework.*` and `org.apache.tika.*` (neither is on the local classpath in this environment) with no errors against any JDK-only construct (`Map.of`, `UUID`, `ByteArrayInputStream`/`ByteArrayOutputStream`, `ImageIO`, or the call into the new `AvatarStorage.store(byte[], String)` signature), confirming the code is structurally sound modulo the two named external dependencies.

## Behaviour changes

- The full upload is now read into memory (`avatar.getBytes()`) instead of streamed straight to disk via `MultipartFile.transferTo()`. Required to inspect and re-encode the content before it is trusted; bounded by whatever multipart size limit Spring already enforces ahead of this handler.
- The response body (the stored file's name) is now a server-generated `UUID.<ext>` value instead of whatever name `AvatarStorage` would have derived from the client's original filename. Required so the client can no longer choose the stored extension.
- Accepted image bytes are re-encoded through `ImageIO.read`/`ImageIO.write` before being written to disk, so the persisted bytes differ from the uploaded bytes even for a legitimate PNG/JPEG. Deliberate: this is what strips a payload appended after the valid image data, which a signature check alone would not catch.
- `AvatarStorage.store()`'s signature changed from `store(MultipartFile avatar)` to `store(byte[] content, String filename)`. Required so the caller passes the Tika-validated bytes and the generated filename explicitly, rather than `AvatarStorage` re-deriving either from the client-controlled `MultipartFile`.
- The on-disk write now uses `Files.write(..., StandardOpenOption.CREATE_NEW)` instead of `MultipartFile.transferTo()`, so it throws `IOException` (surfaced as a 500, same as any other `IOException` in this handler) if the target name already exists rather than silently overwriting it. Collision odds are negligible with a UUID-based name; this follows the language guidance's storage recommendation.
- An upload whose bytes pass the Tika signature check but that `ImageIO.read` cannot decode into a `BufferedImage` (a truncated or malformed file) is now rejected with 400 instead of proceeding to storage. This is a stricter rejection introduced by the same content-validation requirement, not a separate change.
