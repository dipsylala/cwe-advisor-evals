## Verdict

- **CWE**: CWE-434 (Unrestricted Upload of File with Dangerous Type)
- **Location**: `AvatarController.java:20` (`avatar.getContentType()`), continuing into `AvatarStorage.java:15-16` (`getOriginalFilename()` / `transferTo()`)
- **Verdict**: exploitable
- **Confidence**: high

## Source

- **Source**: `avatar` — the `MultipartFile` bound from the multipart request body via `@RequestParam` on `POST /profile/avatar`. Both its content-type and its original filename are client-supplied HTTP request metadata, not verified by Spring or the servlet container.
- **Trace**:
  1. `AvatarController.upload()` reads `avatar.getContentType()` (line 20) and checks it against an allowlist of `"image/png"` / `"image/jpeg"`. This header is set by the uploading client and is trivially forged — an attacker can send a `.jsp`/`.php`/HTML payload with `Content-Type: image/png` and pass the check.
  2. The unvalidated `MultipartFile` is then passed whole to `AvatarStorage.store(avatar)`.
  3. Inside `store()`, `avatar.getOriginalFilename()` (also client-supplied and unvalidated) is resolved directly against `storageDir` and used as the on-disk filename, and `avatar.transferTo(target)` writes the raw, unverified bytes to that path.
- **Sink**: `AvatarStorage.transferTo(target)`, writing content whose type was never checked against its actual bytes, under a name the client chose.
- **Sink contract** (current code): `store()` returns the stored file's name (`String`) to the caller, which the controller echoes back as the HTTP response body. It discards nothing security-relevant — there's simply no validation to discard. It leaves the file extension, storage filename, and file bytes entirely as supplied by the client (all implicit/unchecked). On failure it propagates `IOException` (e.g., traversal-resolved path issues, disk errors) uncaught, which the controller also does not catch, resulting in a 500.

Because the only gate is a check against a forgeable header, and the accepted file is then stored under an attacker-chosen name with its original bytes untouched, the path from source to sink is live and unauthenticated content of any type can be persisted to disk.

## Fix

**Library recommendation**: Apache Tika (`org.apache.tika:tika-core`) for content-sniffing detection, per the loaded Java guidance. The guidance does not carry a minimum safe version for this library — confirm the resolved version against your SCA/dependency-check tooling before merging; no `pom.xml`/`build.gradle` was provided in this case, so the dependency addition is described rather than shown as a diff.

**Vulnerable code** (`AvatarController.java`):

```java
@PostMapping("/profile/avatar")
public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
    String contentType = avatar.getContentType();               // client-supplied header, trusted
    if (!"image/png".equals(contentType) && !"image/jpeg".equals(contentType)) {
        return ResponseEntity.badRequest().body("unsupported avatar");
    }

    return ResponseEntity.ok(storage.store(avatar));             // raw MultipartFile passed on
}
```

**Vulnerable code** (`AvatarStorage.java`):

```java
public String store(MultipartFile avatar) throws IOException {
    Path target = storageDir.resolve(avatar.getOriginalFilename()); // client-supplied filename used as storage path
    avatar.transferTo(target);                                      // raw, unverified bytes written as-is
    return target.getFileName().toString();
}
```

**Fixed code** (`AvatarController.java`):

```java
package cases.upload;

import java.io.IOException;
import org.apache.tika.Tika;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class AvatarController {
    private static final Tika TIKA = new Tika();

    private final AvatarStorage storage;

    public AvatarController(AvatarStorage storage) {
        this.storage = storage;
    }

    @PostMapping("/profile/avatar")
    public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
        byte[] content = avatar.getBytes();
        String detectedType = TIKA.detect(content);
        if (!"image/png".equals(detectedType) && !"image/jpeg".equals(detectedType)) {
            return ResponseEntity.badRequest().body("unsupported avatar");
        }

        return ResponseEntity.ok(storage.store(content, detectedType));
    }
}
```

**Fixed code** (`AvatarStorage.java`):

```java
package cases.upload;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.UUID;
import javax.imageio.ImageIO;

public class AvatarStorage {
    private final Path storageDir;

    public AvatarStorage(Path storageDir) {
        this.storageDir = storageDir;
    }

    public String store(byte[] content, String detectedType) throws IOException {
        String formatName = "image/png".equals(detectedType) ? "png" : "jpg";
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(content));
        if (image == null) {
            throw new IOException("uploaded content could not be decoded as " + formatName);
        }

        String generatedName = UUID.randomUUID() + "." + formatName;
        Path target = storageDir.resolve(generatedName);
        try (OutputStream out = Files.newOutputStream(target, StandardOpenOption.CREATE_NEW)) {
            ImageIO.write(image, formatName, out);
        }
        return target.getFileName().toString();
    }
}
```

## Explanation

The fix replaces the forgeable `Content-Type` header check with a content-sniffing check (`Tika.detect(bytes)`), which inspects the actual file bytes rather than client-asserted metadata, so a script or HTML payload mislabeled as `image/png` is now rejected. The controller passes downstream only the Tika-detected, allowlist-matched type — not the raw header or filename — completing the taint break called for by the guidance's "break taint after allowlist validation" step. `AvatarStorage` no longer derives the storage filename or extension from client input at all: the name is a fresh `UUID`, and the extension is chosen from the allowlisted detected type rather than `getOriginalFilename()`, which also closes the path-traversal exposure that `storageDir.resolve(avatar.getOriginalFilename())` previously carried. Because signature/prefix detection alone can pass a polyglot file (valid image header, malicious payload appended after the image data), `store()` also decodes and re-encodes the image via `ImageIO` before writing, which discards anything that isn't valid pixel data for the detected format; a file that only *looks* like an image at the header is rejected here when `ImageIO.read` returns `null`. Writing with `StandardOpenOption.CREATE_NEW` instead of `transferTo` additionally prevents silently overwriting an existing file if a `UUID` were ever to collide. As a secondary control (not shown, no properties file was in scope), set `spring.servlet.multipart.max-file-size`/`max-request-size` in `application.properties` to bound upload size.

## Behaviour changes

- **Controller no longer trusts `getContentType()`**: replaced with `Tika.detect()` on the actual bytes. Reason: the header is client-controlled and is the vulnerability being fixed.
- **`store()` signature changed from `store(MultipartFile)` to `store(byte[], String detectedType)`**: the controller now must read the file into memory (`avatar.getBytes()`) to sniff its content before storage, and passes the already-validated, canonical type through instead of the raw `MultipartFile`. Reason: required to break taint after allowlist validation per the loaded guidance, and to let `store()` derive the extension from a trusted value rather than re-deriving it from client input.
- **Stored filename changed from the client's original filename to a generated `UUID`-based name**: reason — using the original filename both trusts an unvalidated string as a path segment (traversal risk) and lets the client pick the served extension; the guidance requires a generated name.
- **Stored extension changed from whatever suffix the client's original filename carried to `.png`/`.jpg` derived from the Tika-detected, allowlisted type**: reason — extension controls how the file may later be served/executed, so it must come from the verified type, not client input.
- **File content is now decoded and re-encoded through `ImageIO` before being written**, rather than the original bytes being streamed to disk via `transferTo()`: reason — signature detection only verifies a prefix; re-encoding strips any payload appended after valid image data (a polyglot bypass) and rejects inputs that decode-fail despite passing detection. This means a technically-valid-but-unusual PNG/JPEG (e.g., an unsupported color profile `ImageIO` can't round-trip) could now be rejected where it previously would have been stored unchanged — an intentional trade-off per the guidance's re-encoding requirement, called out here as the guidance instructs when a contract can't be fully preserved.
- **Write uses `Files.newOutputStream(..., StandardOpenOption.CREATE_NEW)` instead of `MultipartFile.transferTo()`**: reason — required to write the re-encoded bytes; `CREATE_NEW` additionally fails safely instead of overwriting on the (extremely unlikely) event of a `UUID` collision, an incidental hardening consistent with the guidance's write-with-`CREATE_NEW` instruction.
- **`IOException` is now also thrown when `ImageIO.read()` fails to decode the content**: reason — this is the mechanism that rejects polyglot/non-image content that passed the Tika prefix check; the controller's existing `throws IOException` already covers this, so no new exception handling is required there, but a caller relying on this endpoint always returning 200/400 should note it can now also surface as a server error for malformed-but-allowlisted-looking content — treat that response the same as any other unexpected I/O failure from this endpoint.
- **Assumptions**: `storageDir`'s location relative to the web root is not shown in the provided files and was not changed; the fix assumes it is already outside served static content as the guidance requires, but this could not be confirmed from the two files in scope. No `pom.xml`/build file was in scope, so the `tika-core` dependency addition is described rather than diffed, and its version is left for SCA/advisory lookup rather than supplied from recall.
