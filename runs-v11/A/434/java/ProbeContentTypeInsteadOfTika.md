## Verdict
**Vulnerable.** `Files.probeContentType()` relies on file extension as a primary signal and is system-dependent, unreliable, and can be bypassed by polyglot files or misnamed malicious content.

## Source
```java
// Line 35-37: Extension is extracted from client-supplied filename
String suffix = (originalFilename != null && originalFilename.contains("."))
        ? originalFilename.substring(originalFilename.lastIndexOf('.'))
        : ".tmp";
Path tempFile = Files.createTempFile("upload-", suffix);
file.transferTo(tempFile);

// Line 42: probeContentType() uses the extension to infer content type
String detectedType = Files.probeContentType(tempFile);
```

The vulnerability is that `Files.probeContentType()` infers MIME type using file extension and system file-type databases. Since the temp file preserves the attacker-controlled extension, `probeContentType()` effectively trusts the client-supplied extension when determining whether to allow the upload.

## Fix
Replace `Files.probeContentType()` with Tika's robust magic-number inspection, which detects file type by reading the actual file content rather than relying on extension:

```java
import org.apache.tika.Tika;

// ...in the upload method:
Tika tika = new Tika();
String detectedType = tika.detect(tempFile);
```

Alternatively, if Tika is unavailable, create the temp file without preserving the extension so `probeContentType()` cannot rely on it:

```java
Path tempFile = Files.createTempFile("upload-", "");  // No suffix
file.transferTo(tempFile);
String detectedType = Files.probeContentType(tempFile);
```

The Tika approach is stronger because it inspects actual file content (magic numbers) instead of system-dependent MIME databases.

## Explanation
CWE-434 occurs when uploaded files are not validated by their actual content before storage. `Files.probeContentType()` is insufficient because:

1. **Extension-dependent**: The method uses file extension as a strong signal; preserving the original filename suffix undermines this
2. **System-dependent**: MIME detection relies on the operating system's incomplete file-type database, which varies across systems
3. **Polyglot files**: Attackers can craft files that are valid in multiple formats (e.g., a ZIP file with a .jpg extension that also has valid JPEG headers), bypassing simple detection
4. **No magic number guarantee**: Unlike Tika, `probeContentType()` does not consistently read and validate file magic numbers

Tika reads actual file content, inspects magic numbers (file signatures), and detects the true format regardless of extension. This makes it suitable for security-relevant upload validation.
