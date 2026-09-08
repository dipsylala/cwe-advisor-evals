## Verdict

Confirmed. `AvatarController.upload()` decides whether an uploaded avatar is safe using only `MultipartFile.getContentType()` (line 20), which is the `Content-Type` value the client sent in the multipart part header. That value is attacker-controlled and has no relationship to the file's real content. `AvatarStorage.store()` then writes the file under `avatar.getOriginalFilename()` — also attacker-controlled — so the extension actually persisted to disk is whatever the client named the file, regardless of what the spoofed `Content-Type` claimed. An attacker can upload a script (e.g. `shell.jsp`, `shell.php`) with the part's `Content-Type` set to `image/png`; the check at line 21 passes, and the file is stored with its dangerous extension intact. If the storage directory is anywhere under a servable/executable path, this is remote code execution; even otherwise, it lets arbitrary extensions and content reach disk under an avatar upload feature.

## Source

`@RequestParam MultipartFile avatar` in `AvatarController.upload()` (`AvatarController.java`, the `avatar` parameter bound from the incoming multipart request). Two attacker-controlled properties of this object flow to the sink unvalidated in a way that matters:

- `avatar.getContentType()` — used as the sole gate (line 20-21) and trivially spoofable.
- `avatar.getOriginalFilename()` — used by `AvatarStorage.store()` to build the on-disk `Path`, which is what determines the actual file type any web server or OS will treat the stored file as.

## Fix

### File: AvatarController.java
```java
package cases.upload;

import java.io.IOException;
import java.io.InputStream;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class AvatarController {
    private final AvatarStorage storage;

    public AvatarController(AvatarStorage storage) {
        this.storage = storage;
    }

    @PostMapping("/profile/avatar")
    public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
        String extension = detectImageExtension(avatar);
        if (extension == null) {
            return ResponseEntity.badRequest().body("unsupported avatar");
        }

        return ResponseEntity.ok(storage.store(avatar, extension));
    }

    // Determines the real image type from the file's signature (magic bytes)
    // instead of the client-supplied Content-Type header, which only reflects
    // what the client claims and can be set independently of the file's
    // actual bytes or name. Returns a fixed, safe extension to store the file
    // under, or null when the content is not a recognized image type.
    private String detectImageExtension(MultipartFile avatar) throws IOException {
        byte[] header = new byte[8];
        int read;
        try (InputStream in = avatar.getInputStream()) {
            read = in.readNBytes(header, 0, header.length);
        }

        if (read >= 4
                && (header[0] & 0xFF) == 0x89 && (header[1] & 0xFF) == 0x50
                && (header[2] & 0xFF) == 0x4E && (header[3] & 0xFF) == 0x47) {
            return ".png";
        }
        if (read >= 3
                && (header[0] & 0xFF) == 0xFF && (header[1] & 0xFF) == 0xD8
                && (header[2] & 0xFF) == 0xFF) {
            return ".jpg";
        }
        return null;
    }
}
```

### File: AvatarStorage.java
```java
package cases.upload;

import java.io.IOException;
import java.nio.file.Path;
import java.util.UUID;
import org.springframework.web.multipart.MultipartFile;

public class AvatarStorage {
    private final Path storageDir;

    public AvatarStorage(Path storageDir) {
        this.storageDir = storageDir;
    }

    public String store(MultipartFile avatar, String extension) throws IOException {
        String filename = UUID.randomUUID() + extension;
        Path target = storageDir.resolve(filename);
        avatar.transferTo(target);
        return target.getFileName().toString();
    }
}
```

## Explanation

The root problem is that two different, independently attacker-controlled signals were conflated: the declared `Content-Type` (used for validation) and the client-supplied filename (used for storage). Trusting the first while acting on the second means the check can be satisfied while the dangerous property — the stored file's extension — is never inspected at all.

The fix removes both attacker-controlled inputs from the trust boundary instead of trying to sanitize them:

- Type validation now reads the first bytes of the uploaded content and checks them against the real PNG (`89 50 4E 47`) and JPEG (`FF D8 FF`) file signatures. This cannot be spoofed by setting a header, because it inspects the bytes that were actually uploaded.
- The stored filename is no longer derived from client input at all. `AvatarStorage.store()` now generates a random `UUID` and appends the extension corresponding to the *verified* signature, so the extension persisted to disk always matches content that was actually confirmed to be an image. This also removes the client's ability to influence the path via `getOriginalFilename()` (e.g. path separators or traversal sequences), as a side effect of no longer using that value at all.
- Only two safe, fixed extensions (`.png`, `.jpg`) can ever be produced by `detectImageExtension()`, so there is no path by which a script extension (`.jsp`, `.php`, `.html`, etc.) can reach `storage.store()`.

A test reproducing the original finding should upload a byte sequence that is not a valid PNG/JPEG signature (e.g. `<% ... %>` with a spoofed `image/png` Content-Type and an `avatar.jsp` filename) and confirm the endpoint returns 400; a second test should upload real PNG/JPEG bytes and confirm the file is stored with a `.png`/`.jpg` extension regardless of the original filename supplied.
