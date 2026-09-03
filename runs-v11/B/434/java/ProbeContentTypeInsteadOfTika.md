## Verdict

VULNERABLE. The code uses `Files.probeContentType()` on a temp file created with the client's original filename suffix. On JDK 9+, `probeContentType()` performs extension-based MIME type lookup rather than inspecting actual file bytes. An attacker can upload a malicious executable (e.g., shell.sh) renamed with an allowed image extension (e.g., shell.jpg) and it will pass validation because the detector sees only the suffix.

## Source

Line 42 calls `Files.probeContentType(tempFile)` on a temporary file that was written at line 38-39. The temp file is created at line 38 with `Files.createTempFile("upload-", suffix)` where `suffix` is derived from the client-supplied `originalFilename` (lines 34-37). The client controls the extension, and `probeContentType()` uses extension-based lookup, making the detection trivial to bypass.

## Fix

Replace `Files.probeContentType(tempFile)` with Apache Tika's byte-based content detection.

### Import
Add to imports:
```java
import org.apache.tika.Tika;
```

### Updated Code
Replace lines 38-42 with:
```java
String originalFilename = file.getOriginalFilename();
Path tempFile = Files.createTempFile("upload-", ".tmp");
file.transferTo(tempFile);

// Detect the real content type by inspecting file bytes, not filename.
// Tika reads the actual file signature (magic bytes) regardless of extension.
byte[] fileBytes = Files.readAllBytes(tempFile);
Tika tika = new Tika();
String detectedType = tika.detect(fileBytes);
```

### Dependency
Add to `pom.xml` (or equivalent build file):
```xml
<dependency>
    <groupId>org.apache.tika</groupId>
    <artifactId>tika-core</artifactId>
    <version>2.9.1</version>
</dependency>
```

## Explanation

**Root cause:** `Files.probeContentType()` on JDK 9+ delegates to OS-level handlers that perform extension-to-MIME mapping. When the temp file retains the client's original suffix, the detector reports the MIME type matching that suffix without reading any bytes. This is a JDK 9+ regression: earlier versions chained a libmagic detector that inspected content; that path was removed.

**Fix mechanism:** Apache Tika's `detect(bytes)` method reads the file's actual byte signature (magic bytes) to determine the real MIME type. A PNG will be detected as `image/png` regardless of its filename; a shell script will be detected as `text/plain` or `application/x-sh` regardless of whether it is named `.jpg`. By stripping the client-supplied suffix from the temp filename and relying on byte-based detection, an attacker cannot forge the MIME type by choosing an extension.

**Why this works:** The allowlist check at lines 44-48 now operates on the true file type, not the claimed type. Rejected files are deleted; accepted files are moved to a UUID-generated name, breaking any connection to the client-supplied extension.

## Behaviour changes

- **New dependency:** `org.apache.tika:tika-core` must be added and present at runtime.
- **Temp file naming:** Temp files are now created with a `.tmp` suffix instead of the client's original suffix. This change is internal and does not affect the final stored filename (which remains UUID-based).
- **Detection mechanism:** File type detection now inspects actual bytes instead of filename. Files with mismatched extension and content (e.g., a shell script named `image.jpg`) will now be rejected if their detected type is not in `ALLOWED_TYPES`.
- **Performance:** Slightly slower than `probeContentType()` because Tika reads file bytes, but negligible for typical upload sizes and necessary for security.
