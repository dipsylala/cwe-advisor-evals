## Verdict

Real issue. The code validates only the `Content-Type` header, which is attacker-controlled, and stores the file using the original filename, allowing malicious uploads.

## Source

**AvatarController.java, line 20:**
```java
String contentType = avatar.getContentType();
```

The vulnerability spans two classes:
1. AvatarController validates only the Content-Type header (lines 20–23), trusting client-supplied metadata.
2. AvatarStorage stores the file under `avatar.getOriginalFilename()` (line 15), using the client-provided name without sanitization.

An attacker can upload a JSP, PHP, or other executable file with a spoofed `Content-Type: image/png` header. The Content-Type check passes, and the file is written to disk with its executable extension, where it can be executed if the storage directory is within the web root.

## Fix

**AvatarController.java:**
```java
@PostMapping("/profile/avatar")
public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
    // Validate file content using magic bytes, not Content-Type header
    byte[] fileHeader = new byte[8];
    try (var is = avatar.getInputStream()) {
        int read = is.read(fileHeader);
        if (read < 8) {
            return ResponseEntity.badRequest().body("invalid file");
        }
    }
    
    // Check PNG signature: 89 50 4E 47
    boolean isPng = fileHeader[0] == (byte) 0x89 && fileHeader[1] == (byte) 0x50 
                  && fileHeader[2] == (byte) 0x4E && fileHeader[3] == (byte) 0x47;
    
    // Check JPEG signature: FF D8 FF
    boolean isJpeg = fileHeader[0] == (byte) 0xFF && fileHeader[1] == (byte) 0xD8 
                   && fileHeader[2] == (byte) 0xFF;
    
    if (!isPng && !isJpeg) {
        return ResponseEntity.badRequest().body("unsupported avatar");
    }
    
    return ResponseEntity.ok(storage.store(avatar));
}
```

**AvatarStorage.java:**
```java
public String store(MultipartFile avatar) throws IOException {
    // Use a UUID-based name, ignoring the client-provided filename
    String safeFilename = UUID.randomUUID().toString() + ".bin";
    Path target = storageDir.resolve(safeFilename);
    avatar.transferTo(target);
    return safeFilename;
}
```

Also add to AvatarStorage imports:
```java
import java.util.UUID;
```

## Explanation

The original code has two weaknesses:

1. **Content-Type header is attacker-controlled.** A malicious client can send any Content-Type value; HTTP does not enforce that it matches the actual file. The check on lines 20–23 only filters by a header the attacker supplies, not by file content.

2. **Original filename is used for storage.** Storing the file as `avatar.getOriginalFilename()` (e.g., `shell.jsp`) allows execution if the directory is within the web root or served by the application. The fix uses a UUID-based name (e.g., `a1b2c3d4-e5f6-4g7h-8i9j-0k1l2m3n4o5p.bin`) so the extension cannot be exploited for code execution.

The remediation validates file content using magic bytes (file signatures), which cannot be spoofed as easily as a header. PNG files always begin with `89 50 4E 47`, and JPEG files always begin with `FF D8 FF`. This check is resilient to attackers who claim a malicious file is an image—the actual bytes must match the expected format.

Additional hardening (optional but recommended):
- Store uploads outside the web root, or in a directory where execution is disabled.
- Set restrictive file permissions on the storage directory.
- Re-encode images server-side (transforming the file, not just renaming it) to strip embedded code.
