## Verdict

Confirmed. The application relies on the client-supplied Content-Type header to validate file type, which is insufficient to prevent arbitrary file upload.

## Source

Line 20 in AvatarController.java retrieves the Content-Type header:
```
String contentType = avatar.getContentType();
```

The subsequent check (lines 21-23) validates only this header against "image/png" and "image/jpeg". An attacker can spoof the Content-Type header while uploading a malicious file (executable, script, archive, etc.). The downstream AvatarStorage.store() method (line 15 in AvatarStorage.java) saves the file using the original filename without validation, allowing the malicious file to be written to disk.

## Fix

Replace the Content-Type header validation with file extension and magic-byte validation:

```java
@PostMapping("/profile/avatar")
public ResponseEntity<String> upload(@RequestParam MultipartFile avatar) throws IOException {
    // Validate file extension
    String filename = avatar.getOriginalFilename();
    if (filename == null || 
        (!filename.toLowerCase().endsWith(".png") && 
         !filename.toLowerCase().endsWith(".jpg") && 
         !filename.toLowerCase().endsWith(".jpeg"))) {
        return ResponseEntity.badRequest().body("unsupported avatar");
    }
    
    // Validate actual file content using magic bytes
    byte[] fileBytes = avatar.getBytes();
    if (!isValidImageFile(fileBytes)) {
        return ResponseEntity.badRequest().body("invalid image file");
    }

    return ResponseEntity.ok(storage.store(avatar));
}

private boolean isValidImageFile(byte[] fileBytes) {
    if (fileBytes.length < 4) {
        return false;
    }
    
    // Check for PNG magic bytes: 89 50 4E 47
    if (fileBytes[0] == (byte) 0x89 && fileBytes[1] == 0x50 && 
        fileBytes[2] == 0x4E && fileBytes[3] == 0x47) {
        return true;
    }
    
    // Check for JPEG magic bytes: FF D8 FF
    if (fileBytes[0] == (byte) 0xFF && fileBytes[1] == (byte) 0xD8 && 
        fileBytes[2] == (byte) 0xFF) {
        return true;
    }
    
    return false;
}
```

## Explanation

The fix applies two independent validation layers:

1. **Extension whitelist**: Validate the original filename ends with an allowed extension (case-insensitive). This rejects files with executable or dangerous extensions at the filename level.

2. **Magic byte validation**: Read the file bytes and verify the file starts with the correct magic bytes (file signature) for PNG (0x89 0x50 0x4E 0x47) or JPEG (0xFF 0xD8 0xFF). This confirms the actual file content matches the claimed type, preventing an attacker from uploading a .exe or .jsp file with a spoofed Content-Type header.

Magic bytes are the first few bytes of a file that identify its true format independent of the filename or Content-Type header. The client cannot forge them without creating a valid image file. This approach stops the attacker from uploading executable code while claiming it is an image.

The filename validation also limits what the downstream storage handler receives, reducing path traversal risk when the storage mechanism uses getOriginalFilename().
