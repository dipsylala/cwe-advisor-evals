## Verdict
Confirmed. The upload endpoint decides whether a file is an "avatar" using only the client-supplied `Content-Type` header, and the storage layer then persists the file under the attacker-supplied original filename (and its extension). Both the type gate and the on-disk name are fully attacker-controlled, so a malicious file can pass the check and land on disk with any extension — including an executable one such as `.jsp` — while wearing a spoofed `image/png` label.

## Source
`AvatarController.upload()` (`AvatarController.java:19-20`) — `MultipartFile avatar` from the `multipart/form-data` request, and specifically `avatar.getContentType()`, which is the raw `Content-Type` sub-part header the client sets on the file part. This value is never derived from the file's actual bytes; it flows unchecked into the type comparison at line 21 and, via `avatar` itself, into `AvatarStorage.store()` where `avatar.getOriginalFilename()` (`AvatarStorage.java:15`) is used verbatim to build the destination path.

## Fix
In `AvatarStorage.java`, stop trusting either attacker-supplied string:

```java
package cases.upload;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.UUID;
import org.apache.tika.Tika;
import org.springframework.web.multipart.MultipartFile;

public class AvatarStorage {
    private static final Tika TIKA = new Tika();
    private static final Map<String, String> ALLOWED_TYPES = Map.of(
        "image/png", ".png",
        "image/jpeg", ".jpg"
    );

    private final Path storageDir;

    public AvatarStorage(Path storageDir) {
        this.storageDir = storageDir;
    }

    public String store(MultipartFile avatar) throws IOException {
        String detectedType;
        try (InputStream in = avatar.getInputStream()) {
            detectedType = TIKA.detect(in);
        }

        String extension = ALLOWED_TYPES.get(detectedType);
        if (extension == null) {
            throw new IOException("unsupported avatar type: " + detectedType);
        }

        String safeName = UUID.randomUUID() + extension;
        Path target = storageDir.resolve(safeName).normalize();
        if (!target.getParent().equals(storageDir.normalize())) {
            throw new IOException("invalid avatar target");
        }

        avatar.transferTo(target);
        return target.getFileName().toString();
    }
}
```

`AvatarController.java` can then drop its own `Content-Type`-based gate entirely (or keep it only as a cheap early-reject optimization) and let `AvatarStorage.store()` raise for anything that isn't real PNG/JPEG data:

```java
@PostMapping("/profile/avatar")
public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
    return ResponseEntity.ok(storage.store(avatar));
}
```

If Tika (`org.apache.tika:tika-core`) is not already a dependency, add it — pin to the current stable release and track it via the project's normal SCA/dependency scan, since content-sniffing libraries periodically patch parser vulnerabilities of their own.

## Explanation
`MultipartFile.getContentType()` returns whatever the client's HTTP request declared for that part; Spring does not inspect the bytes. An attacker uploading a JSP web shell simply sets the part's `Content-Type` to `image/png` and the check at line 21 passes without ever looking at the payload. The original design's second, independent flaw compounds this: even if the content-type check were somehow trustworthy, `AvatarStorage.store()` still wrote the file using `avatar.getOriginalFilename()`, so the file kept whatever extension the attacker chose (e.g. `shell.jsp`) rather than one implied by the declared type — meaning the two attacker-controlled values (header and filename) didn't even have to agree.

The fix addresses both halves. First, it replaces the header trust with content sniffing (Apache Tika's magic-byte detection) performed on the actual uploaded bytes, so the accept/reject decision reflects what the file *is*, not what the client claims it is. Second, it derives the stored file's extension from that verified type via a small allowlist, and generates the base filename itself (`UUID.randomUUID()`) instead of reusing any part of the client-supplied name — eliminating both the dangerous-extension path and any path-traversal risk from `getOriginalFilename()`. The `normalize()`/parent check is a defense-in-depth guard confirming the resolved target still lives inside `storageDir` before the file is written. Together these ensure only genuine image bytes are persisted, under a filename the server fully controls.
