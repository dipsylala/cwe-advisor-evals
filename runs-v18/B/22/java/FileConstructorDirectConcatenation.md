## Verdict

Exploitable. Attacker-controlled filename parameter is used to construct a file path without validation or canonicalization, enabling directory traversal attacks. An attacker can supply payloads like `../../../etc/passwd` to read files outside the intended document store directory.

## Source

`request.getParameter("file")` at line 32 of DocumentDownloadServlet.java. The HTTP request parameter is user-supplied and untrusted.

## Fix

### File: DocumentDownloadServlet.java

```java
package com.example.docs;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Serves a document from the shared document store so that a signed-in
 * user can download a file that was previously uploaded to the team's
 * workspace.
 */
@WebServlet("/documents/download")
public class DocumentDownloadServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final String DOCUMENT_STORE_DIR =
            "/var/lib/appdata/document-store";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String fileName = request.getParameter("file");
        if (fileName == null || fileName.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing file parameter");
            return;
        }

        // Reject if the supplied name is not a single path component
        Path fileNamePath = Paths.get(fileName).getFileName();
        if (fileNamePath == null || !fileName.equals(fileNamePath.toString())) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid file name");
            return;
        }

        // Canonicalize base directory
        Path baseDir = Paths.get(DOCUMENT_STORE_DIR).toRealPath();
        
        // Construct, canonicalize and validate the requested file path
        Path requestedPath;
        try {
            requestedPath = baseDir.resolve(fileName).toRealPath();
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Document not found");
            return;
        }

        // Verify the resolved path is within the base directory
        if (!requestedPath.startsWith(baseDir)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid file name");
            return;
        }

        response.setContentType("application/octet-stream");
        response.setHeader(
                "Content-Disposition", "attachment; filename=\"" + fileName + "\"");

        try (InputStream in = new FileInputStream(requestedPath.toFile());
                OutputStream out = response.getOutputStream()) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
    }
}
```

## Explanation

The fix eliminates path traversal by implementing three complementary controls from the CWE-22 guidance:

1. **Single-component validation** (line 44-47): Rejects filenames containing path separators (`/` or `\`), relative path sequences like `..`, or absolute paths. The check `Paths.get(fileName).getFileName().toString()` extracts only the final path component; if the result differs from the original input, traversal sequences or separators are present and the request is rejected.

2. **Canonical path resolution** (line 50-57): Converts both the base directory and the requested file to their absolute canonical form by calling `toRealPath()`, which resolves symbolic links and eliminates relative references like `..` and `.`. The resolved path represents the actual filesystem location the application will read from.

3. **Containment verification** (line 60-62): After canonicalization, verifies that the resolved file path is within the base directory using `Path.startsWith(Path)` with `Path` objects, not string prefix matching. This prevents symlink attacks and sibling-directory confusion that string-based checks allow.

If any check fails, the application returns an error response without proceeding to file access. The remediated code now uses the canonicalized path for all subsequent operations, eliminating the earlier gap where the path could be re-derived differently between validation and use.

## Behaviour changes

- **Request validation added**: Requests with multi-component filenames (containing `/` or `\`), relative path sequences (`..`), or absolute paths are now rejected with SC_BAD_REQUEST instead of being processed.
- **Path resolution changed**: The path is now constructed with `Path.resolve()` instead of manual string concatenation, and canonicalized with `toRealPath()` before use, which follows symlinks and resolves relative references.
- **Error handling changed**: Non-existent files are now detected via IOException from `toRealPath()` instead of an explicit `exists()` check, with the same SC_NOT_FOUND response.
- **File reference changed**: The file is accessed via `requestedPath.toFile()` (the canonicalized Path object) instead of the original `requestedFile` variable, ensuring all operations use the validated path.

These changes maintain the original error message behavior and file serving semantics while closing the traversal vulnerability. The `Content-Disposition` header still uses the original (validated) `fileName` parameter to preserve the user-facing filename in downloads.
