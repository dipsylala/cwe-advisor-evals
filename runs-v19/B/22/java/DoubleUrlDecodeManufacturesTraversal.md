## Verdict

Exploitable. The vulnerability is a double URL decode that manufactures path traversal. An attacker can send a doubly-encoded traversal sequence (e.g., `%252e%252e%252fetc%252fpasswd`) which survives the servlet container's automatic decode in percent-encoded form, then is deliberately re-decoded by line 38, revealing the traversal payload to the `File` constructor on line 46.

## Source

`request.getParameter("file")` at line 30. The servlet container percent-decodes this parameter automatically, yielding `rawFilename`. The vulnerability flows from the application then performing a second `URLDecoder.decode()` on this already-decoded value (line 38), which re-interprets percent-encoded sequences that the servlet had left intact and manufactures a path traversal.

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

        String rawFilename = request.getParameter("file");
        if (rawFilename == null || rawFilename.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "file parameter is required");
            return;
        }

        // Canonicalize the path and verify it stays within the base directory.
        // Do not perform a second URLDecoder.decode() - the servlet container
        // already percent-decoded the parameter value, and re-decoding manufactures
        // traversal from an inert double-encoded value like %252e%252e%252f.
        Path baseDir;
        Path targetPath;
        File target;
        
        try {
            baseDir = Paths.get(ATTACHMENTS_DIR).toRealPath();
            targetPath = baseDir.resolve(rawFilename).toRealPath();
            
            if (!targetPath.startsWith(baseDir)) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
                return;
            }
            
            target = targetPath.toFile();
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found or not accessible");
            return;
        }

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

The fix eliminates the double-decode vulnerability by removing the second `URLDecoder.decode()` call entirely (originally at line 38). The servlet container has already percent-decoded the request parameter once, yielding plain text. Applying `URLDecoder.decode()` a second time interprets any remaining percent-encoded sequences in that plain text as directives to decode further, turning an inert literal like `%2e%2e%2f` into the active traversal sequence `../`.

The replacement approach uses Java's NIO Path API for canonicalization and containment enforcement: `Path.toRealPath()` resolves all symbolic links and relative references (`.`, `..`) to their absolute canonical form, and `Path.startsWith(Path)` verifies the resolved target path is within the base directory using path-component-aware comparison—a string prefix check would fail to catch a sibling directory like `/var/app-data/attachments-backup`.

This eliminates both the manufactured traversal and the brittle `..` substring check. The second `URLDecoder.decode()` is the source of the weakness; removing it prevents the manufacturing of traversal payloads from double-encoded input.

## Behaviour changes

1. **Removed second `URLDecoder.decode()` call** (original line 38) — This was manufacturing the vulnerability by re-interpreting percent-encoding that the servlet had already decoded. The value is used directly as-is after the servlet's automatic decode.

2. **Added path canonicalization and containment verification** — Replaces the insufficient `if (filename.contains(".."))` check with proper containment validation. The canonicalization step resolves the full path to its real form (following symlinks), and `startsWith()` enforces that the result stays within the base directory. This is more robust than substring matching and handles edge cases like symlinked parent directories.

3. **Added IOException handling for path resolution** — Wraps the canonicalization logic in a try-catch to handle cases where the path does not exist or is not accessible, returning HTTP 404 instead of propagating the exception.

4. **Changed header filename source** — Uses `rawFilename` directly instead of the second-decoded `filename`, since the servlet has already decoded the value to plain text and no second decode is needed or safe.

5. **Added explicit variable declarations** — Separates path resolution into distinct variables (`baseDir`, `targetPath`, `target`) for clarity and to ensure the validated path is the one actually used in the file operation.

All changes preserve the original functionality: the servlet continues to serve files from the attachment directory to authorized users, but now does so safely without permitting path traversal.
