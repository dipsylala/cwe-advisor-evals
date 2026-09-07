## Verdict
**Vulnerable.** The code validates only the HTTP `Content-Type` header without verifying the actual file contents. An attacker can upload an executable file while declaring a safe MIME type (e.g., `image/jpeg`) in the header, bypassing the allowlist check.

## Source
Line 45: `Files.copy(file.getInputStream(), destination, StandardCopyOption.REPLACE_EXISTING);`

The vulnerability exists because:
- Line 33–36: Only the `Content-Type` header is checked, which originates from the client request and is easily spoofed.
- Lines 40–42: The filename and storage location are determined solely from the spoofed content type.
- Line 45: The unvalidated file is copied to disk without confirming its actual format.

## Fix
Add magic byte validation to confirm the file content matches the declared MIME type before accepting the upload:

```java
// Validate magic bytes to confirm file content matches the declared content type
byte[] fileBytes = file.getBytes();
if (!isValidImageMagicBytes(fileBytes, contentType)) {
    return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body("File content does not match declared type");
}
```

Add a helper method to check file signatures:

```java
private static boolean isValidImageMagicBytes(byte[] bytes, String contentType) {
    if (bytes.length < 3) {
        return false;
    }

    if ("image/png".equals(contentType)) {
        // PNG magic bytes: 89 50 4E 47
        return bytes.length >= 4 && bytes[0] == (byte) 0x89 && bytes[1] == 0x50 && 
               bytes[2] == 0x4E && bytes[3] == 0x47;
    } else if ("image/jpeg".equals(contentType)) {
        // JPEG magic bytes: FF D8 FF
        return bytes[0] == (byte) 0xFF && bytes[1] == (byte) 0xD8 && bytes[2] == (byte) 0xFF;
    }

    return false;
}
```

Insert the validation check before line 45, immediately after the Content-Type allowlist check (after line 36).

## Explanation
CWE-434 requires validation of both the declared type and the actual file format. The Content-Type header is controlled by the attacker and cannot be trusted as the sole validation mechanism. Magic bytes (file signatures) are embedded in the file itself and cannot be spoofed without changing the file structure.

For images:
- PNG files must begin with the 4-byte signature `89 50 4E 47`.
- JPEG files must begin with the 3-byte signature `FF D8 FF`.

Checking these signatures before accepting and storing the file ensures that a malicious executable cannot be uploaded even if the attacker sets a fake Content-Type header. This defence-in-depth approach prevents the stored file from containing unexpected content types that could be executed or processed as scripts by downstream consumers.
