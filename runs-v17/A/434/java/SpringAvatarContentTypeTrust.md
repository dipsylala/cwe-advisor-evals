## Verdict
The finding is valid. The code relies on the Content-Type header and user-supplied filename, both spoofable by an attacker, to validate and store uploaded files. An attacker can upload malicious executables (e.g. JSP, PHP) that the server will execute, enabling remote code execution.

## Source
User-supplied `MultipartFile avatar` in `AvatarController.upload()`.

## Fix

### File: AvatarController.java
```java
package cases.upload;

import java.io.IOException;
import java.util.UUID;
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
        // Validate file extension against allowlist
        String filename = avatar.getOriginalFilename();
        if (filename == null || !isAllowedExtension(filename)) {
            return ResponseEntity.badRequest().body("unsupported avatar format");
        }

        // Validate actual file content by checking file signature (magic bytes)
        if (!isValidImageFile(avatar)) {
            return ResponseEntity.badRequest().body("unsupported avatar");
        }

        // Get file extension for storage
        String extension = getExtension(filename);
        return ResponseEntity.ok(storage.store(avatar, extension));
    }

    private boolean isAllowedExtension(String filename) {
        String lower = filename.toLowerCase();
        return lower.endsWith(".png") || lower.endsWith(".jpg") || lower.endsWith(".jpeg");
    }

    private String getExtension(String filename) {
        int lastDot = filename.lastIndexOf('.');
        return lastDot > 0 ? filename.substring(lastDot) : ".png";
    }

    private boolean isValidImageFile(MultipartFile file) throws IOException {
        byte[] bytes = file.getBytes();
        if (bytes.length < 4) {
            return false;
        }

        // Check PNG magic bytes: 89 50 4E 47
        if (bytes[0] == (byte) 0x89 && bytes[1] == 0x50 && bytes[2] == 0x4E && bytes[3] == 0x47) {
            return true;
        }

        // Check JPEG magic bytes: FF D8 FF
        if (bytes[0] == (byte) 0xFF && bytes[1] == (byte) 0xD8 && bytes[2] == (byte) 0xFF) {
            return true;
        }

        return false;
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
        // Use a safe, server-generated filename instead of the user-supplied one
        // This prevents attackers from uploading files with dangerous extensions
        String safeFilename = UUID.randomUUID().toString() + extension;
        Path target = storageDir.resolve(safeFilename);
        avatar.transferTo(target);
        return safeFilename;
    }
}
```

## Explanation
The vulnerability stems from trusting two attacker-controlled inputs:

1. **Content-Type header**: Can be spoofed. A browser sends `Content-Type: image/jpeg` for any file, regardless of actual content.
2. **Original filename**: Comes from the client and may contain dangerous extensions like `.jsp`, `.php`, or `.exe`.

The fix addresses this through three layers of validation and safe handling:

**Layer 1 - Extension allowlist**: Checks the filename extension against a whitelist of safe values (`.png`, `.jpg`, `.jpeg`). This prevents obvious attack vectors with dangerous extensions.

**Layer 2 - Magic byte validation**: Reads the actual file bytes and checks for image file signatures (PNG: `89 50 4E 47`, JPEG: `FF D8 FF`). This confirms the file is actually an image, not malware disguised with a spoofed Content-Type. An attacker cannot forge these bytes while creating valid executables in most cases.

**Layer 3 - Safe filename storage**: Generates a new filename using `UUID.randomUUID()` and the validated extension. This replaces the user-supplied filename, ensuring the stored file cannot be interpreted as an executable by the web server (e.g., cannot be `.jsp` or `.php`).

The fix preserves the original behavior (validating to `image/png` and `image/jpeg`) while closing the attack surface. An attacker can no longer upload arbitrary files by spoofing the Content-Type or using dangerous extensions.
