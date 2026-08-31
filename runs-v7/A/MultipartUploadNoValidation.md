## Verdict
CWE-434: Unrestricted upload of dangerous file type. The code accepts and saves uploaded files without validating file extension, MIME type, or filename. This allows attackers to upload executable files (JSP, PHP, .exe) that could be executed by the web server, or use path traversal sequences in the filename to write to arbitrary directories.

## Source
Line 21 is the sink (`file.transferTo(destination)`), but the vulnerability originates from line 18—the direct use of user-supplied `originalFilename` without any validation. The filename is used unsanitized to construct a destination path (line 19) and written without extension or type checks.

## Fix
Implement three layers of protection:

1. **Extension whitelist**: Validate that the file extension matches a safe set. Extract the extension from `originalFilename`, convert to lowercase, and reject if not in a whitelist such as `["pdf", "png", "jpg", "jpeg", "gif", "txt"]`.

2. **Filename sanitization**: Strip or reject path traversal sequences (`../`, `..\\`, null bytes, absolute paths). Use `new File(originalFilename).getName()` to extract just the filename component, rejecting any result that differs from the input.

3. **Safe filename generation**: Generate a new filename independent of user input (e.g., using UUID or timestamp) and append only the validated extension. Example: `UUID.randomUUID().toString() + ".pdf"`.

Revised code:

```java
import java.util.Set;
import java.util.UUID;

@PostMapping("/upload")
public String handleUpload(@RequestParam("file") MultipartFile file) throws IOException {
    String originalFilename = file.getOriginalFilename();
    
    // Validate extension against whitelist
    Set<String> allowedExtensions = Set.of("pdf", "png", "jpg", "jpeg", "gif", "txt");
    String extension = extractExtension(originalFilename).toLowerCase();
    if (!allowedExtensions.contains(extension)) {
        throw new IllegalArgumentException("File type not allowed");
    }
    
    // Validate filename does not contain path traversal
    File nameCheck = new File(originalFilename);
    if (!nameCheck.getName().equals(originalFilename)) {
        throw new IllegalArgumentException("Invalid filename");
    }
    
    // Generate safe filename
    String safeFilename = UUID.randomUUID().toString() + "." + extension;
    File destination = new File(UPLOAD_DIR + safeFilename);
    
    file.transferTo(destination);
    return "Uploaded to " + destination.getAbsolutePath();
}

private String extractExtension(String filename) {
    if (filename == null || !filename.contains(".")) {
        return "";
    }
    return filename.substring(filename.lastIndexOf(".") + 1);
}
```

## Explanation
CWE-434 occurs when uploaded files are not restricted by type. Without validation, an attacker uploads a JSP or PHP file to a directory served by the application server, gaining code execution. Alternatively, path traversal in the filename (`../../web-inf/classes/malicious.class`) writes outside the intended directory.

The fix uses three independent checks:

- **Whitelist validation** ensures only expected file types are accepted, preventing executable uploads. The whitelist is determined by what the application legitimately needs.

- **Filename normalization** (`File.getName()`) catches path traversal attempts and verifies the input contains no directory separators; any mismatch is rejected.

- **UUID-based naming** decouples the stored filename from user input, eliminating filename-based attacks entirely. The validated extension is appended to preserve functionality.

Together, these prevent both direct uploads of dangerous types and indirect execution via path manipulation.
