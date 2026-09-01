## Verdict

Confirmed. The application trusts the Content-Type HTTP header (`avatar.getContentType()`) on line 20 to validate uploaded files as images. An attacker can forge this header to upload executable files (JSP, class, etc.) that bypass validation and are then stored with the original, unsanitized filename in AvatarStorage, creating a file upload vulnerability.

## Source

Line 20 in AvatarController.java:
```java
String contentType = avatar.getContentType();
```

The `getContentType()` method returns the client-supplied Content-Type header, which is trivial to spoof. The subsequent validation on lines 21-23 checks only this header value, not actual file contents. Combined with the unsanitized filename handling in AvatarStorage.store() (line 15: `avatar.getOriginalFilename()`), an attacker can upload malicious files.

## Fix

1. **Do not validate based on Content-Type header.** Remove or disable the check on lines 21-23 that reads `avatar.getContentType()`.

2. **Validate actual file content via magic bytes.** Read the first few bytes of the uploaded file and verify they match the expected image format signatures:
   - PNG: `89 50 4E 47` (hex)
   - JPEG: `FF D8 FF` (hex)
   Use a library like Apache Commons Imaging or validate manually by reading the file's first bytes before accepting it.

3. **Sanitize the filename.** Replace `avatar.getOriginalFilename()` with a safe name:
   - Use a UUID or hash-based filename (e.g., `UUID.randomUUID().toString() + ".png"`)
   - Or strip the original extension and re-add only `.png` or `.jpg` after content validation
   - Never pass user-supplied filenames directly to `Path.resolve()` without validation

4. **Store uploads outside the web root.** Ensure uploaded files are not stored in a web-accessible directory where the server might execute them as dynamic content (JSP, class files, etc.).

5. **Set correct Content-Type on download.** When serving the stored file, explicitly set the response Content-Type to `image/png` or `image/jpeg` based on what you validated, not based on the uploaded file's original name.

## Explanation

The Content-Type HTTP header is entirely client-controlled and not a reliable indicator of file type. An attacker can upload a malicious JSP, compiled Java class, or other executable file and spoof the Content-Type header as "image/png" to bypass the validation on line 20-23. The file is then stored using its original, unsanitized filename in AvatarStorage, allowing the attacker to either predict its location and request its execution, or use path traversal techniques (e.g., `../../../shell.jsp`) to place it in a location where it will be executed. The remediation requires validating the actual file content (via magic bytes or binary analysis), not the client-supplied header, and ensuring filenames cannot be abused for code execution or directory traversal.
