## Verdict

The vulnerability is real and exploitable. The application applies a second URLDecoder after the container has already decoded once, which allows attackers to bypass the simple `..` containment check via double-encoded traversal sequences. The canonical fix is to remove the second decode and implement proper path canonicalization with `toRealPath()` and containment verification with `startsWith()`.

## Source

**File:** `AttachmentDownloadServlet.java`  
**Vulnerable Line:** 46  
**Taint Source:** `request.getParameter("file")` at line 30  
**Taint Flow:**
1. Parameter obtained at line 30 (already container-decoded once)
2. Incorrectly decoded a second time at line 38 with `URLDecoder.decode()`
3. Insufficient check at line 40 (only searches for literal `..`)
4. Sink: `new File(ATTACHMENTS_DIR, filename)` at line 46

The double-decoding allows an attacker to send a double-encoded traversal sequence that bypasses the simple string check and becomes traversal after the second decode.

## Fix

### File: AttachmentDownloadServlet.java

```java
package com.example.attachments;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Serves previously-uploaded attachments back to the requesting user.
 *
 * The attachment store keeps every uploaded file flat under ATTACHMENTS_DIR,
 * named after the original filename supplied at upload time.
 */
public class AttachmentDownloadServlet extends HttpServlet {

    private static final String ATTACHMENTS_DIR = "/var/app-data/attachments";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // request.getParameter() has already been percent-decoded once by the
        // servlet container, so rawFilename is already plain text at this point.
        String rawFilename = request.getParameter("file");
        if (rawFilename == null || rawFilename.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "file parameter is required");
            return;
        }

        // Do not apply additional URL decoding - the container has already decoded once.
        // Canonicalize and verify the path stays within the base directory.
        try {
            Path baseDir = Paths.get(ATTACHMENTS_DIR).toRealPath();
            Path targetPath = baseDir.resolve(rawFilename).toRealPath();
            
            // Verify the resolved path is within the base directory
            if (!targetPath.startsWith(baseDir)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "access denied");
                return;
            }
            
            File target = targetPath.toFile();
            
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=\"" + rawFilename + "\"");

            try (InputStream in = new FileInputStream(target);
                 OutputStream out = response.getOutputStream()) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    out.write(buffer, 0, read);
                }
            }
        } catch (NoSuchFileException e) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "file not found");
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "error serving file");
        }
    }
}
```

## Explanation

The fix eliminates the vulnerability by removing the unsafe second `URLDecoder.decode()` call and replacing it with proper path canonicalization using `java.nio.file.Path`.

**Key changes:**
- Removed `URLDecoder.decode()` at line 38: The container already decoded the parameter once; applying a second decode manufactures traversal opportunities
- Added `Path.toRealPath()` calls to fully canonicalize both the base directory and target path, resolving symlinks and relative path components (`.`, `..`)
- Added `Path.startsWith()` containment check to verify the resolved target path is within the approved base directory using path-component-aware comparison, not string prefixes
- Wrapped the operation in try-catch to gracefully handle `NoSuchFileException` (file not found) and other `IOException` scenarios

This ensures that:
1. No attacker-controlled input can control the filepath directly
2. All relative path sequences and symlink tricks are resolved before containment is verified
3. The canonicalization is path-component-aware, preventing false positives like `/app/uploads-backup` matching `/app/uploads`

## Behaviour changes

- **Error handling:** The fix now returns `SC_NOT_FOUND` (404) specifically when a file doesn't exist, and `SC_INTERNAL_SERVER_ERROR` (500) for other IO errors, whereas the original code would throw an unhandled exception if the file didn't exist
- **Symlink handling:** The fix now follows symlinks and verifies they don't escape the base directory, whereas the original code accepted any symlink destination
- **Request parameter handling:** The fix no longer applies a second URL decode, which means filenames with encoded characters like `%20` (space) or `%2e` (literal dot) will be preserved as-is, not over-decoded. This prevents ambiguity and double-encoding attacks
- **Security posture:** The fix rejects any path that resolves outside ATTACHMENTS_DIR, including those constructed via `..`, absolute paths, or symlinks—stricter than the original literal `..` check

All changes are backward-compatible for legitimate file requests within the attachments directory.
