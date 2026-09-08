## Verdict
The vulnerability is confirmed. Line 20 extracts the `Content-Type` header from the client request and uses it as the sole basis for file type validation. The `Content-Type` header is client-controlled and can be spoofed, allowing an attacker to upload malicious executable files (e.g., JSP, executable scripts) with a forged image MIME type. Combined with the use of the original filename in `AvatarStorage.store()`, an attacker can achieve arbitrary file upload and potential code execution.

## Source
The vulnerability is in the validation logic at lines 20-23 of `AvatarController.java`. The code checks:
```
String contentType = avatar.getContentType();
if (!"image/png".equals(contentType) && !"image/jpeg".equals(contentType)) {
    return ResponseEntity.badRequest().body("unsupported avatar");
}
```
The `getContentType()` method returns the `Content-Type` header value from the request, which is entirely client-controlled. An attacker can upload any file while claiming it is an image by setting this header.

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
    private final Tika tika;

    public AvatarController(AvatarStorage storage) {
        this.storage = storage;
        this.tika = new Tika();
    }

    @PostMapping("/profile/avatar")
    public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
        String detectedType = tika.detect(avatar.getInputStream());
        if (!"image/png".equals(detectedType) && !"image/jpeg".equals(detectedType)) {
            return ResponseEntity.badRequest().body("unsupported avatar");
        }

        return ResponseEntity.ok(storage.store(avatar));
    }
}
```

## Explanation
The fix replaces client-provided `Content-Type` header validation with server-side validation of the actual file content using Apache Tika. Tika inspects the file's magic bytes (file signature) to determine its true type, not the client-supplied header. This prevents an attacker from bypassing the file type check by spoofing the `Content-Type` header.

The change:
- Adds `org.apache.tika.Tika` dependency for robust file type detection based on file content
- Calls `tika.detect(avatar.getInputStream())` to examine the actual bytes of the uploaded file
- Compares the detected MIME type against the allowed list instead of the client-provided header

This ensures only files that are genuinely PNG or JPEG images are accepted, regardless of what the client claims in the `Content-Type` header.
