## Verdict

The vulnerability is confirmed. The code validates the Content-Type header against an allowlist but does not verify the file's actual content. An attacker can upload a malicious executable (e.g., a JSP, PHP, or compiled binary) by setting a spoofed Content-Type header (e.g., "image/png"), causing it to be saved as an image file where it may be executed depending on server configuration.

## Source

The vulnerability is at line 45: `Files.copy(file.getInputStream(), destination, StandardCopyOption.REPLACE_EXISTING);`

The code validates only the Content-Type header (`file.getContentType()` at line 33) without checking the file's magic bytes. The Content-Type header is provided by the client and can be arbitrarily set.

## Fix

Add magic byte verification to confirm the uploaded file is actually an image matching its declared content type. Use Apache Commons IO's `TikaInputStream` or check magic bytes manually. Update the imports and modify the upload handler:

```java
import org.apache.tika.Tika;
import java.util.Map;

// In the uploadImage method, after the content type allowlist check:
Tika tika = new Tika();
String detectedType = tika.detect(file.getInputStream());

if (!ALLOWED_CONTENT_TYPES.contains(detectedType)) {
    return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
            .body("File content does not match allowed image types");
}

// Reset stream after detection, since it was read
file.getInputStream().reset();
```

Alternatively, without a library, check the first few bytes (magic bytes) manually:

```java
private static final Map<String, byte[]> MAGIC_BYTES = Map.of(
    "image/png", new byte[]{(byte) 0x89, 0x50, 0x4E, 0x47},
    "image/jpeg", new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF}
);

// After the content type allowlist check:
byte[] header = new byte[4];
try (var is = file.getInputStream()) {
    is.read(header);
    byte[] expectedMagic = MAGIC_BYTES.get(contentType);
    if (expectedMagic == null || !Arrays.equals(Arrays.copyOf(header, expectedMagic.length), expectedMagic)) {
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                .body("File does not match declared content type");
    }
}

// Now copy the file
Files.copy(file.getInputStream(), destination, StandardCopyOption.REPLACE_EXISTING);
```

The Tika approach is preferred for production systems as it uses comprehensive magic byte databases and handles format variations.

## Explanation

CWE-434 occurs when file upload validation relies solely on client-controlled metadata (Content-Type header, filename extension) without verifying the actual file content. Magic bytes (file signatures) are the bytes at the start of a file that identify its true format. They cannot be spoofed by setting a header and provide reliable verification of file type.

The fix validates that the uploaded file's magic bytes match one of the allowed image formats before saving it. This prevents an attacker from uploading executable content (JSP, PHP, shell scripts, ELF binaries) that could be executed by the web server despite having an image extension and spoofed image Content-Type header.

The Tika library (`org.apache.tika:tika-core`) is the standard approach in Java and handles the full range of format detection automatically. If using the manual magic-byte approach, handle stream resets carefully to allow re-reading after detection.
