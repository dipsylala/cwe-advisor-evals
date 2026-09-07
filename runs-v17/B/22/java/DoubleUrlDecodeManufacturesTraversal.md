## Verdict
exploitable

## Source
Line 30: `request.getParameter("file")` receives user-supplied filename.

## Fix

### File: AttachmentDownloadServlet.java

```java
package com.example.attachments;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
    private static final Path BASE_DIR = Paths.get(ATTACHMENTS_DIR);

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

        // Verify filename is a single path component (no directory separators or traversal sequences)
        if (!Paths.get(rawFilename).getFileName().toString().equals(rawFilename)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
            return;
        }

        // Construct the target path by combining the base directory with the filename
        Path targetPath = BASE_DIR.resolve(rawFilename);

        // Canonicalize the path and verify it stays within the base directory
        Path canonical;
        try {
            canonical = targetPath.toRealPath();
            Path baseCanonical = BASE_DIR.toRealPath();
            if (!canonical.startsWith(baseCanonical)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "access denied");
                return;
            }
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "file not found");
            return;
        }

        File target = canonical.toFile();

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
    }
}
```

## Explanation

The vulnerability was a double URL-decoding issue combined with insufficient path validation. The servlet container automatically percent-decodes the request parameter once, but the original code applied `URLDecoder.decode()` a second time. An attacker sending `file=%252e%252e%252f` (double-encoded) would be decoded to `%2e%2e%2f` by the container, then to `../` by the application, bypassing the weak `.contains("..")` check and allowing path traversal. The fix eliminates the second decode and replaces the weak string check with proper path canonicalization. The code now validates that the filename is a single path component using `Paths.get(name).getFileName().toString().equals(name)`, canonicalizes the full path with `Path.toRealPath()` (which follows symlinks and fails if the file doesn't exist), and verifies the canonical path stays within the base directory using `Path.startsWith()` on `Path` objects, not string comparison. This prevents directory traversal even when facing encoded or symbolic-link-based attacks.

## Behaviour changes

- Removed the `URLDecoder.decode()` call on line 38, which was double-decoding an already-decoded parameter
- Replaced the weak `.contains("..")` check with validation that filename is a single path component
- Added `Path.toRealPath()` to canonicalize paths and follow symlinks
- Added `Path.startsWith()` check to verify containment within the base directory using component-aware comparison
- Changed error response codes: `SC_NOT_FOUND` (404) for missing files instead of attempting the open and failing, `SC_FORBIDDEN` (403) for paths outside the base directory
- Added `IOException` catch block to handle missing files and symlink resolution failures
- The file reading behavior remains identical: same content-type, same streaming buffer, same response format

