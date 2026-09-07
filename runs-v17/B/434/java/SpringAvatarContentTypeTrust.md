# CWE-434 Remediation: SpringAvatarContentTypeTrust

## Verdict

Exploitable. The controller validates uploads by checking the client-supplied `Content-Type` HTTP header alone, which is trivially forged. An attacker can upload an executable file (e.g., JSP, JSP shell) by setting the `Content-Type` to `image/png` and the file will pass validation and be written to disk using its original filename. The storage sink then persists the file at a path derived from client input without content verification.

## Source

`AvatarController.java`, line 19-20: `@RequestParam MultipartFile avatar` and the client-controlled `Content-Type` header accessed via `avatar.getContentType()`.

## Fix

### File: AvatarController.java

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
    private final AvatarStorage storage;
    private final Tika tika = new Tika();

    public AvatarController(AvatarStorage storage) {
        this.storage = storage;
    }

    @PostMapping("/profile/avatar")
    public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
        byte[] bytes = avatar.getBytes();
        String detectedType = tika.detect(bytes);

        if (!"image/png".equals(detectedType) && !"image/jpeg".equals(detectedType)) {
            return ResponseEntity.badRequest().body("unsupported avatar");
        }

        return ResponseEntity.ok(storage.store(avatar, detectedType));
    }
}
```

### File: AvatarStorage.java

```java
package cases.upload;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.UUID;
import javax.imageio.ImageIO;
import org.apache.tika.mime.MimeTypes;
import org.apache.tika.mime.MimeTypeException;
import org.springframework.web.multipart.MultipartFile;

public class AvatarStorage {
    private final Path storageDir;

    public AvatarStorage(Path storageDir) {
        this.storageDir = storageDir;
    }

    public String store(MultipartFile avatar, String detectedType) throws IOException {
        String extension = getExtensionForType(detectedType);
        if (extension == null || extension.isEmpty()) {
            throw new IOException("Unable to determine extension for type: " + detectedType);
        }

        String filename = UUID.randomUUID().toString() + "." + extension;
        Path target = storageDir.resolve(filename);

        reencodeAndStore(avatar, target, detectedType);
        return filename;
    }

    private String getExtensionForType(String mimeType) throws IOException {
        try {
            MimeTypes mimeTypes = MimeTypes.getDefaultMimeTypes();
            org.apache.tika.mime.MimeType mime = mimeTypes.forName(mimeType);
            return mime.getExtension().replaceFirst("^\\.", "");
        } catch (MimeTypeException e) {
            throw new IOException("Unrecognized MIME type: " + mimeType, e);
        }
    }

    private void reencodeAndStore(MultipartFile avatar, Path target, String detectedType)
            throws IOException {
        try {
            BufferedImage image = ImageIO.read(avatar.getInputStream());
            if (image == null) {
                throw new IOException("Failed to read image data");
            }
            String formatName = detectedType.equals("image/png") ? "PNG" : "JPEG";
            ImageIO.write(image, formatName, Files.newOutputStream(target, StandardOpenOption.CREATE_NEW));
        } catch (IOException e) {
            throw new IOException("Failed to process and store avatar: " + e.getMessage(), e);
        }
    }
}
```

## Explanation

The fix replaces the client-supplied `Content-Type` header check with actual byte-content inspection using Apache Tika (`tika.detect(bytes)`), which reads the file's magic bytes to identify its true type. Tika's detection cannot be bypassed by forging a header—an attacker uploading a JSP will be correctly identified as `application/x-jsp`, not `image/png`, and the upload will be rejected before reaching storage.

The storage layer then accepts only the validated MIME type (passed from the controller as a trusted parameter), uses Tika to derive the file extension safely, and generates a random UUID filename instead of reusing the client-supplied original filename. This prevents both path traversal attacks through the filename and the attacker controlling the stored filename. Finally, images are re-encoded (decoded via `ImageIO.read()` and re-written with `ImageIO.write()`) to strip embedded scripts, metadata, and polyglot payloads that a raw byte transfer would preserve. The file is written with `StandardOpenOption.CREATE_NEW`, which atomically fails if the path already exists, adding a race-condition defense.

## Behaviour changes

- **Filename format**: Stored avatars are now named with a random UUID plus extension (e.g., `550e8400-e29b-41d4-a716-446655440000.png`) instead of the original client-supplied filename. This removes user-facing filename control and prevents path traversal. **Reason**: Required for safe storage and to break taint after validation.

- **File content on disk**: Images are re-encoded before storage. Pixel data is preserved, but EXIF, other metadata, and any embedded polyglot content are discarded. **Reason**: Re-encoding strips embedded scripts and validates the file is readable as a real image.

- **Memory usage during upload**: The entire file is now loaded into a byte array (`avatar.getBytes()`) and then re-read by `ImageIO`, rather than streamed directly. For typical avatar sizes (< 5 MB), this is acceptable; very large uploads may require a streaming decode approach not shown here. **Reason**: Tika detection requires bytes in memory; re-encoding requires full image parsing.

- **Method signature change in AvatarStorage**: `store(MultipartFile)` is now `store(MultipartFile, String detectedType)`. Callers must pass the validated MIME type. **Reason**: Enforces use of the validated type, not the raw request value, in storage logic.

- **Error handling**: New `IOException` thrown on unrecognized MIME types or failed image reading. Previously, non-image files would be stored as-is with their original names. **Reason**: Strict rejection of untrusted content is the intended security posture.

- **New dependency**: Apache Tika (`org.apache.tika:tika-core`). No minimum version specified by the CWE guidance; confirm the current version against SCA tooling before merging.
