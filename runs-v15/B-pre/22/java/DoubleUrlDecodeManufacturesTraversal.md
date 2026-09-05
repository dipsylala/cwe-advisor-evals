## Verdict

Real path traversal vulnerability. The second `URLDecoder.decode()` call on line 38 re-decodes an already-decoded request parameter, transforming an inert literal like `%2e%2e%2f` into an exploitable `../` sequence. The subsequent check for `..` catches the obvious attempt but is brittle - a path-canonicalization-based fix is required.

## Source

User input enters at line 30 via `request.getParameter("file")`, which is already percent-decoded by the servlet container. The data flows to line 38 where a second `URLDecoder.decode()` call manufactures traversal sequences from inert encoded literals. The sink is the `File` constructor at line 46.

The vulnerability is introduced at the second decode (line 38), not caught fully by the `contains("..")` check (line 40), and exposed at the sink (line 46 `new File(ATTACHMENTS_DIR, filename)`).

## Fix

Remove the second `URLDecoder.decode()` call and replace the `contains("..")` validation with proper path canonicalization and containment checking using `java.nio.file.Path`.

```java
package com.example.attachments;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
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

        // Do NOT decode again - the container has already decoded the request parameter.
        // Construct the candidate path and canonicalize it.
        Path baseDir = Paths.get(ATTACHMENTS_DIR).toRealPath();
        Path targetPath = baseDir.resolve(rawFilename).toRealPath();

        // Verify the canonicalized target stays within the base directory.
        if (!targetPath.startsWith(baseDir)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
            return;
        }

        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\"" + rawFilename + "\"");

        try (InputStream in = Files.newInputStream(targetPath);
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

The vulnerability is a classic "double decode manufactures traversal" scenario. The servlet container decodes `request.getParameter()` once, so if a client sends `file=%252e%252e%252f` (doubly encoded), it arrives in the code as `%2e%2e%2f` (singly encoded, appearing as a literal string). The second `URLDecoder.decode()` call then transforms this literal into `../`, creating a real traversal sequence. Although the subsequent `contains("..")` check would catch this particular attempt, this pattern is fragile and relies on a blacklist approach.

The fix removes the second decode entirely, since `request.getParameter()` already returns decoded text. It then uses `Path.toRealPath()` to canonicalize the target path (resolving symlinks and relative references like `..` to their true destinations), and `Path.startsWith(Path)` to verify that the canonical target path remains within the base directory. This ensures that regardless of encoding tricks or symlink tricks, the file access is confined to the intended directory. The containment check uses path-component-aware comparison, not string prefix matching, which prevents sibling-directory escapes like `/var/app-data/attachments-backup`.

## Behaviour changes

- Removed the second `URLDecoder.decode()` call that was manufacturing traversal sequences.
- Added `import` for `java.nio.file.Files`, `Path`, and `Paths`.
- Replaced the weak `contains("..")` check with canonical path resolution and containment verification using `Path.toRealPath()` and `Path.startsWith()`.
- Changed the file access from `new FileInputStream(target)` to `Files.newInputStream(targetPath)` to use the canonicalized path directly.
- The filename passed to the `Content-Disposition` header now uses `rawFilename` (the user-provided value) for display, not the traversal-validated `filename`, avoiding information leakage about the normalized path.
