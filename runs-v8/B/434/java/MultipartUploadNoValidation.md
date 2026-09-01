## Verdict

Exploitable. The upload handler accepts files without validating their content type or filename, and stores them in a webroot directory using the original filename. An attacker can upload a malicious executable, JSP, or script file that the server will execute, or use path traversal sequences in the filename to write files outside the intended directory.

## Source

`MultipartFile file` parameter at line 17 - the uploaded file from the HTTP POST request is attacker-controlled. The filename from `getOriginalFilename()` at line 18 is a client-supplied HTTP header, not validated by the server.

## Fix

**Vulnerable code (lines 18-21):**
```java
        String originalFilename = file.getOriginalFilename();
        File destination = new File(UPLOAD_DIR + originalFilename);
        // SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
        file.transferTo(destination);
```

**Fixed code:**
```java
        // Sniff the actual file content type from file bytes
        Tika tika = new Tika();
        byte[] fileBytes = file.getBytes();
        String detectedMimeType = tika.detect(fileBytes);
        
        // Validate against allowlist of permitted types
        Set<String> allowedMimeTypes = Set.of("image/jpeg", "image/png", "application/pdf");
        if (!allowedMimeTypes.contains(detectedMimeType)) {
            throw new IllegalArgumentException("File type not allowed");
        }
        
        // Map detected MIME type to safe extension
        Map<String, String> mimeToExtension = Map.ofEntries(
            Map.entry("image/jpeg", ".jpg"),
            Map.entry("image/png", ".png"),
            Map.entry("application/pdf", ".pdf")
        );
        String extension = mimeToExtension.get(detectedMimeType);
        
        // Generate random filename with detected type's extension
        String randomFilename = UUID.randomUUID().toString() + extension;
        File destination = new File(UPLOAD_DIR + randomFilename);
        
        file.transferTo(destination);
```

**Required imports and class changes:**
- Add import: `import org.apache.tika.Tika;`
- Add import: `import java.util.UUID;`
- Add import: `import java.util.Set;`
- Add import: `import java.util.Map;`
- Add Maven dependency: `org.apache.tika:tika-core` (current version from Maven Central)

## Explanation

The fix eliminates the vulnerability through three mechanisms. First, it validates the actual file content by sniffing the file's magic bytes using Apache Tika (`tika.detect(fileBytes)`), which inspects the first bytes of the file rather than trusting the client-supplied `Content-Type` header or filename extension. Second, it enforces an allowlist of permitted MIME types; any file whose detected type is not in the allowlist is rejected immediately. Third, it breaks the taint chain by generating a new random filename using `UUID.randomUUID()` and deriving the extension from a fixed server-controlled map based on the detected MIME type, never using the original filename. This eliminates both the arbitrary-file-write risk (from path traversal in the original filename) and the code-execution risk (from uploading executable file types to the webroot). For maximum safety in production, additionally consider re-encoding image uploads through `ImageIO.read()` and `ImageIO.write()` to strip embedded scripts, and store files outside the webroot entirely.

## Behaviour changes

**Arguments and control flow changed:**
- New validation gate: file is now rejected if detected MIME type is not in the allowlist (changes behavior by preventing upload of disallowed types; this is intentional and closes the weakness).
- Filename generation: original filename is completely discarded; storage now uses a random UUID + detected-type extension. This changes the stored filename (no longer predictable or user-controlled) but preserves the ability to serve files back by storing the mapping, if needed.

**New dependencies introduced:**
- `org.apache.tika:tika-core` must be added to the project's Maven `pom.xml` or Gradle `build.gradle` for Tika to be available. This is a third-party library addition required to perform reliable content sniffing.

**Exception handling:**
- The fixed code throws `IllegalArgumentException` if the detected file type is not in the allowlist. The original code did not perform this validation, so callers must be prepared to handle this new exception (either in a try-catch at the endpoint or by letting Spring's exception handler convert it to a 400 Bad Request response).

**No changes to:**
- The sink (`file.transferTo(destination)`) remains unchanged; it still writes the file to disk.
- The storage directory remains `/var/www/html/uploads/`; for production, move this outside the webroot to prevent direct execution.
- The response message format; the path returned to the client is still the destination's absolute path.
