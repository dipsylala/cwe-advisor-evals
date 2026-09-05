## Verdict

Exploitable

## Source

`MultipartFile avatar` parameter from HTTP POST request at `/profile/avatar` endpoint (AvatarController.java:19)

## Fix

**Vulnerable code (AvatarController.java:18-26):**
```java
@PostMapping("/profile/avatar")
public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
    String contentType = avatar.getContentType();  // Client-supplied, untrusted
    if (!"image/png".equals(contentType) && !"image/jpeg".equals(contentType)) {
        return ResponseEntity.badRequest().body("unsupported avatar");
    }

    return ResponseEntity.ok(storage.store(avatar));  // Uses original filename
}
```

**Fixed AvatarController.java:**
```java
@PostMapping("/profile/avatar")
public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
    byte[] bytes = avatar.getBytes();
    
    // Detect actual content type by inspecting bytes, not client header
    Tika tika = new Tika();
    String detectedType = tika.detect(bytes);
    
    // Validate against allowlist of permitted types
    if (!"image/png".equals(detectedType) && !"image/jpeg".equals(detectedType)) {
        return ResponseEntity.badRequest().body("unsupported avatar");
    }
    
    // Generate random filename with extension derived from detected type
    String extension = "image/png".equals(detectedType) ? "png" : "jpg";
    String randomFilename = UUID.randomUUID().toString() + "." + extension;
    
    return ResponseEntity.ok(storage.store(avatar, randomFilename));
}
```

**Fixed AvatarStorage.java:**
```java
public class AvatarStorage {
    private final Path storageDir;

    public AvatarStorage(Path storageDir) {
        this.storageDir = storageDir;
    }

    public String store(MultipartFile avatar, String validatedFilename) throws IOException {
        Path target = storageDir.resolve(validatedFilename);
        avatar.transferTo(target);
        return target.getFileName().toString();
    }
}
```

**Dependency requirement:**
Add Apache Tika to `pom.xml` or `build.gradle`:
```xml
<dependency>
    <groupId>org.apache.tika</groupId>
    <artifactId>tika-core</artifactId>
    <version>[check SCA for minimum safe version]</version>
</dependency>
```

## Explanation

The original code validates the file type by checking `avatar.getContentType()`, which is an HTTP header value supplied by the client and can be trivially spoofed. An attacker can upload a malicious JSP web shell or executable file while sending a forged `Content-Type: image/png` header, bypassing the validation. The code then uses `avatar.getOriginalFilename()` directly as the storage path without validation, which could contain path traversal sequences or dangerous extensions.

The fix replaces header-based validation with actual content inspection: Apache Tika detects the file type by reading magic bytes (file signature), which cannot be spoofed. Only the detected type is allowed through. A random filename is generated based on the Tika-detected type, mapped through a fixed extension allowlist to produce a safe storage name that the server, not the attacker, controls. The validated filename is passed to storage, replacing the untrusted original.

## Behaviour changes

- **Pre-reads file into memory**: `avatar.getBytes()` loads the entire upload into memory for Tika detection. For large files, consider using Tika's streaming API: `tika.detect(avatar.getInputStream())` instead.
- **Storage method signature changes**: `store(MultipartFile, String)` now takes a second parameter for the pre-validated filename. Callers must pass a server-generated, validated name.
- **Extension mapping responsibility shifts**: Extension selection moves from client-provided filename to server-controlled allowlist derived from detected type. This is intentional and closes the weakness.
- **Requires additional dependency**: Apache Tika must be added to the build manifest.
- **Return value unchanged**: Still returns the stored filename string as before.
