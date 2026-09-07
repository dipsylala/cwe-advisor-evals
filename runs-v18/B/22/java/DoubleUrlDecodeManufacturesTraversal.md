## Verdict

Path traversal vulnerability confirmed. The code applies a second `URLDecoder.decode()` to user input that the servlet container has already decoded, manufacturing traversal from URL-encoded sequences like `%2e%2e%2f`. This double-decode bypass occurs before the insufficient check on line 40, which only searches for the literal string `..` in the already-decoded value. An attacker sending a double-encoded traversal sequence (e.g., `%252e%252e%252fpasswd`) passes the early check and becomes exploitable after the second decode.

## Source

**File:** `AttachmentDownloadServlet.java`  
**Entry point:** `request.getParameter("file")` (line 30) - value is already percent-decoded by servlet container  
**Transformation (vulnerable):** `URLDecoder.decode(rawFilename, "UTF-8")` (line 38) - applies unnecessary second decode  
**Insufficient validation:** `filename.contains("..")` (line 40) - only checks the *decoded* value and does not validate containment within the intended directory  
**Sink:** `new File(ATTACHMENTS_DIR, filename)` (line 46) - constructs path with untrusted decoded filename; `FileInputStream(target)` (line 51) - opens the resolved file

**Data flow:**
1. Attacker sends `file=%252e%252e%252fetc%252fpasswd` (double URL-encoded `../etc/passwd`)
2. Servlet container decodes once: `rawFilename` becomes `%2e%2e%2fetc%2fpasswd` (still encoded)
3. Line 38 decodes again: `filename` becomes `../etc/passwd` (now exploitable)
4. Line 40 check fails to catch because check was testing the *previous* string that wasn't yet decoded
5. Line 46 constructs path using `../`, allowing directory traversal to `/var/etc/passwd`

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

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // request.getParameter() has already been percent-decoded once by the
        // servlet container. Do not apply URLDecoder.decode() again - double-
        // decoding manufactures traversal from inert literals like %2e%2e%2f.
        String filename = request.getParameter("file");
        if (filename == null || filename.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "file parameter is required");
            return;
        }

        // Reject traversal sequences and null bytes
        if (filename.contains("..") || filename.contains("\0")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
            return;
        }

        try {
            // Canonicalize both base and target paths to resolve symlinks and
            // relative references. toRealPath() requires the target to exist;
            // if not found, it throws NoSuchFileException, which we catch.
            Path baseDir = Paths.get(ATTACHMENTS_DIR).toRealPath();
            Path targetPath = baseDir.resolve(filename).toRealPath();

            // Verify the resolved path is contained within the base directory,
            // using path-component comparison to avoid false positives like
            // /var/app-data/attachments-secret passing a string prefix check.
            if (!targetPath.startsWith(baseDir)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
                return;
            }

            File target = targetPath.toFile();

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
        } catch (java.nio.file.NoSuchFileException e) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
        }
    }
}
```

## Explanation

The vulnerability stems from applying `URLDecoder.decode()` to a value that the servlet container has already decoded. The HTTP parameter `file` is automatically percent-decoded by the servlet container before reaching `request.getParameter()`, so the value is already in plain text. A second decode manufactures exploitable sequences: an attacker's double-encoded payload (`%252e%252e%252f`, representing URL-encoded `%2e%2e%2f`) survives the first container decode as `%2e%2e%2f` (inert), passes the insufficient check on line 40 (which only searches for `..` in the already-decoded value at that moment), then is decoded a second time on line 38 to become `../` (exploitable).

The fix removes the second `URLDecoder.decode()` call entirely, accepting the filename as already decoded by the container. It adds two defenses:

1. **Early rejection:** Rejects any filename containing `..` or null bytes, rejecting traversal sequences before path construction.

2. **Canonical path validation:** Canonicalizes both the base directory and the target path using `toRealPath()`, which resolves symlinks and relative references (`.`, `..`) to absolute paths. The check `targetPath.startsWith(baseDir)` then verifies the resolved path is contained within the base directory using path-component comparison (avoiding false positives like a sibling directory named `attachments-secret`).

If the file does not exist (expected for invalid filenames or missing files), `toRealPath()` throws `NoSuchFileException`, caught and returned as a 404. This is correct behavior for a download endpoint.

## Behaviour changes

- **Double-encoded traversal now rejected:** Payloads like `%252e%252e%252fpasswd` no longer bypass validation. The second decode no longer occurs, so the double-encoded sequence remains as the literal string `%2e%2e%2fpasswd` (which does not match any real file).

- **More precise validation:** Validation now uses canonical path comparison instead of string containment. Paths are resolved to their true locations (following symlinks), and containment is checked at the path-component level, preventing false positives like sibling directories.

- **File-not-found handling:** If the requested file does not exist (or is outside the permitted directory), the response is now a 404 (via caught `NoSuchFileException`) rather than a 500 from an unhandled `FileInputStream` exception. This is more appropriate for a download endpoint.

- **Removed second decoding:** The `URLDecoder` import is no longer used. Clients no longer need to worry about interaction between client-side encoding and server-side re-decoding.
