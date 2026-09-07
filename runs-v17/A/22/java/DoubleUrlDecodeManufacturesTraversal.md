## Verdict

The vulnerability is real. Double URL decoding at line 38 bypasses the weak path traversal check, allowing an attacker to inject `../` sequences through double-encoded payloads.

## Source

E:/Github/cwe-advisor/evals/cases/22/java/DoubleUrlDecodeManufacturesTraversal/AttachmentDownloadServlet.java, line 46.

The vulnerable code pattern:
1. Parameter `rawFilename` is already decoded once by the servlet container (line 30)
2. Code applies a second `URLDecoder.decode()` at line 38, decoding percent-encoded sequences that should remain as-is
3. Weak validation with `contains("..")` at line 40 is insufficient and does not run on canonical paths
4. Attack: double-encode traversal (e.g., `%252e%252e%252f`) to bypass the check and construct a path outside the allowed directory

## Fix

### File: AttachmentDownloadServlet.java

```java
package com.example.attachments;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
        // servlet container, so filename is already plain text at this point.
        String filename = request.getParameter("file");
        if (filename == null || filename.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "file parameter is required");
            return;
        }

        // Do NOT decode again - the container has already decoded once.
        // Decoding twice allows an attacker to bypass path traversal checks.

        File attachmentsDir = new File(ATTACHMENTS_DIR);
        File target = new File(attachmentsDir, filename);

        // Use canonical paths to resolve all path traversal attempts.
        // This defeats .., ., symlinks, and other path manipulation techniques.
        try {
            String targetCanonical = target.getCanonicalPath();
            String dirCanonical = attachmentsDir.getCanonicalPath();

            // Verify the resolved path is within the allowed directory.
            if (!targetCanonical.startsWith(dirCanonical + File.separator) &&
                !targetCanonical.equals(dirCanonical)) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
                return;
            }
        } catch (IOException e) {
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

**Changes made:**

1. **Removed `URLDecoder.decode()` call** (line 38 in original): The servlet container has already performed one URL decode on the request parameter. A second decode is unnecessary and creates a gadget for attackers—they can double-encode traversal sequences to bypass subsequent validation. Example: attacker sends `%252e%252e%252f` (double-encoded `../`), which is decoded by the container to `%2e%2e%2f`, then by the vulnerable code to `../`, bypassing the string-based check.

2. **Replaced weak `contains("..")` check with canonical path validation**: String matching for `".."` is fragile—it fails against encoded alternatives, symlinks, and null bytes. Instead, we:
   - Resolve both the target and the attachment directory to their **canonical absolute paths** using `File.getCanonicalPath()`
   - Verify that the target's canonical path is either equal to or starts with the directory's path plus a separator
   - This approach defeats all path traversal encoding, `.` and `..` sequences, and symlink attacks

3. **Added `IOException` handling** for `getCanonicalPath()`: Path resolution can fail if the file doesn't exist or permissions are denied. We catch these and reject the request safely.

The fix converts a weak, encoding-dependent check into a robust path-containment validation that works regardless of encoding or path manipulation attempts.

