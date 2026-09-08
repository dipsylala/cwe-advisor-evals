## Verdict
CONFIRMED - Path traversal vulnerability via double URL decoding and insufficient path validation.

## Source
Line 46 in AttachmentDownloadServlet.java. The sink is `new File(ATTACHMENTS_DIR, filename)` used to open a file for download without verifying the resolved path stays within the base directory.

## Fix

### File: AttachmentDownloadServlet.java

```java
package com.example.attachments;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLDecoder;
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

        // Some older clients double-encode the filename, so decode again to
        // normalize it before validating and building the path.
        String filename = URLDecoder.decode(rawFilename, "UTF-8");

        // First-pass validation: reject obvious traversal attempts and absolute paths
        if (filename.contains("..") || filename.startsWith("/")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
            return;
        }

        // Construct and validate the target path using canonical resolution
        File baseDir = new File(ATTACHMENTS_DIR);
        File target = new File(baseDir, filename);
        
        // Resolve both paths to their canonical (absolute, symlink-resolved) forms
        String canonicalPath = target.getCanonicalPath();
        String canonicalBaseDir = baseDir.getCanonicalPath();
        
        // Verify the target is within the base directory
        if (!canonicalPath.startsWith(canonicalBaseDir + File.separator)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
            return;
        }

        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");

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

The fix adds defense-in-depth against path traversal:

1. **Retained checks** (line 40): The original ".." and new "/" checks provide fast rejection of obvious traversal patterns before expensive file I/O.

2. **Canonical path resolution** (lines 52-53): `getCanonicalPath()` resolves the target path to its absolute form, eliminating relative segments like ".." and following symlinks to their actual targets. This defeats encoding tricks that might bypass string matching.

3. **Confinement verification** (lines 58-60): After canonical resolution, the code verifies that the target path starts with the base directory path plus a separator. This ensures:
   - Absolute paths in the filename parameter cannot escape the directory
   - Symlinks cannot point outside the directory  
   - Relative path attacks are resolved and checked

The vulnerability worked because double-decoding `%252F` to `/` could inject an absolute path that the simple string check for ".." would miss, and `new File()` treats absolute child paths as taking precedence over the parent directory.
