## Verdict
The vulnerability is confirmed. The code trusts the client-provided `Content-Type` header to validate file type, which allows attackers to upload arbitrary files (e.g., malicious executables) by spoofing the Content-Type as `image/png` or `image/jpeg`.

## Source
Line 20 in `AvatarController.java`:
```java
String contentType = avatar.getContentType();
if (!"image/png".equals(contentType) && !"image/jpeg".equals(contentType)) {
    return ResponseEntity.badRequest().body("unsupported avatar");
}
```

The `getContentType()` method returns the `Content-Type` header sent by the client, which is not a reliable indicator of actual file contents. A malicious client can send any content with a spoofed `image/png` header.

## Fix
Replace the Content-Type header check with validation of the actual file signature (magic bytes):

```java
@PostMapping("/profile/avatar")
public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
    byte[] header = new byte[8];
    avatar.getInputStream().read(header);
    
    boolean isPng = header.length >= 4 && 
        (byte)0x89 == header[0] && 
        (byte)0x50 == header[1] && 
        (byte)0x4E == header[2] && 
        (byte)0x47 == header[3];
    
    boolean isJpeg = header.length >= 3 && 
        (byte)0xFF == header[0] && 
        (byte)0xD8 == header[1] && 
        (byte)0xFF == header[2];
    
    if (!isPng && !isJpeg) {
        return ResponseEntity.badRequest().body("unsupported avatar");
    }

    return ResponseEntity.ok(storage.store(avatar));
}
```

Additionally, in `AvatarStorage.store()`, generate a safe filename based on the detected content type rather than trusting the original filename:

```java
public String store(MultipartFile avatar, String detectedExtension) throws IOException {
    String safeFilename = UUID.randomUUID().toString() + "." + detectedExtension;
    Path target = storageDir.resolve(safeFilename);
    avatar.transferTo(target);
    return safeFilename;
}
```

## Explanation
CWE-434 occurs when an application accepts file uploads without validating the actual file contents. The `Content-Type` header is controlled by the client and cannot be trusted as evidence of file type. An attacker can upload a malicious executable, script, or other dangerous file by simply setting the `Content-Type` to `image/png`.

The fix validates the file's actual magic bytes (file signature), which identify the true file type regardless of headers or extensions. PNG files always begin with the bytes `89 50 4E 47`, and JPEG files always begin with `FF D8 FF`. This is the primary defense for CWE-434.

Secondary hardening includes generating a safe filename (avoiding path traversal via `..` or absolute paths) and storing with an extension that matches the detected content type, so the file cannot be executed even if it reaches a web-accessible directory.
