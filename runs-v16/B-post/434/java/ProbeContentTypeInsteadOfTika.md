## Verdict

Exploitable. An attacker can upload a dangerous file type (e.g., executable, web shell) by bypassing validation, because `Files.probeContentType()` on JDK 9+ examines only the file name (extension), not the bytes. The temp file was created with a client-supplied extension, so a renamed EXE uploaded as `shell.pdf` will be detected as PDF and pass the allowlist check.

## Source

`file.getOriginalFilename()` at line 34. The filename's extension is extracted at lines 35–37, used to create a temp file at line 38 (with `Files.createTempFile("upload-", suffix)`), and the content is written at line 39 (`file.transferTo(tempFile)`). The attacker controls the extension through the original filename.

## Fix

Replace line 42 (`String detectedType = Files.probeContentType(tempFile)`) with Apache Tika's content detection, which inspects actual file bytes:

**Before:**
```java
String detectedType = Files.probeContentType(tempFile);
```

**After:**
```java
byte[] fileBytes = Files.readAllBytes(tempFile);
String detectedType = new Tika().detect(fileBytes);
```

**Additional imports:**
```java
import org.apache.tika.Tika;
```

**Dependency:**
Add Apache Tika Core to `pom.xml`:
```xml
<dependency>
    <groupId>org.apache.tika</groupId>
    <artifactId>tika-core</artifactId>
    <version>2.9.1</version>
</dependency>
```

**Hardening: Stored filename extension**

Additionally, the stored filename at line 50 should include an extension derived from the detected type (lines 50–52), not stored bare. Update:

**Before:**
```java
String storedName = UUID.randomUUID().toString();
Path destination = UPLOAD_DIR.resolve(storedName);
Files.move(tempFile, destination, StandardCopyOption.REPLACE_EXISTING);
```

**After:**
```java
String storedName = UUID.randomUUID().toString();
String ext = "";
try {
    ext = MimeTypes.getDefaultMimeTypes().forName(detectedType).getExtension();
} catch (Exception e) {
    // Type recognized by Tika but no standard extension; store without extension
}
Path destination = UPLOAD_DIR.resolve(storedName + ext);
Files.move(tempFile, destination, StandardCopyOption.REPLACE_EXISTING);
```

**Additional import:**
```java
import org.apache.tika.mime.MimeTypes;
```

## Explanation

`Files.probeContentType()` is unreliable for validation on JDK 9+ because it performs extension-to-MIME lookup from the file name only, not content inspection. Tika's `tika.detect(bytes)` reads the file's actual bytes and checks magic bytes (file signatures) to determine type reliably. This closes the vulnerability because an attacker can no longer disguise a dangerous file type (executable, script, archive) by renaming it with a safe extension.

The stored filename modification ensures that the file will later be served back with the correct type (or no type), determined by the server's detected type and not the attacker's original extension. This prevents interpretation of the stored file as an executable or script if it is accidentally served or executed.

## Behaviour changes

1. **File type detection now inspects bytes instead of extension**: `tika.detect(fileBytes)` replaces `Files.probeContentType(tempFile)`. The original code examined only the temp file's name; the fix reads and inspects content. This is a security fix with no functional regression—the allowlist still validates the same set of types, but now against the true content.

2. **Stored filenames now include an extension**: The generated UUID is appended with an extension derived from the detected MIME type (or empty string if no standard extension exists). The original code stored files as bare UUIDs. This change affects how the files are later served or cached (browsers and CDNs may use extension for Content-Type inference as a fallback), but does not alter the core upload/validation flow. The security benefit is that if a file is ever directly accessed or served by a file server outside the application, its extension will match its content, preventing misinterpretation.

3. **Tika creation**: Two `new Tika()` instances are created (one in the content detection, one in extension lookup). This is lightweight; Tika reuses internal MIME type registry across instances.

4. **MimeTypeException handling**: The try-catch at line ~56 silently skips the extension if the detected type has no standard extension. This preserves the current behavior (files are stored with whatever extension can be derived) and does not break the upload flow; it is not a silent data loss.
