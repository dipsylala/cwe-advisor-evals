## Verdict

exploitable

## Source

User-supplied `fileName` parameter from HTTP request via `request.getParameter("file")` at line 32. The parameter is checked for null/empty but never validated to ensure it remains within the intended directory.

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

        try {
            Path baseDir = Paths.get(DOCUMENT_STORE_DIR).toRealPath();
            Path requestedPath = baseDir.resolve(fileName).toRealPath();

            if (!requestedPath.startsWith(baseDir)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
                return;
            }

            File requestedFile = requestedPath.toFile();

            response.setContentType("application/octet-stream");
            response.setHeader(
                    "Content-Disposition", "attachment; filename=\"" + fileName + "\"");

            try (InputStream in = new FileInputStream(requestedFile);
                    OutputStream out = response.getOutputStream()) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Document not found");
        }
    }
}
```

## Explanation

The vulnerability allowed path traversal attacks via sequences like `../` in the fileName parameter. The original code concatenated user input directly into a file path without canonicalizing or validating that the result stayed within the intended directory.

The fix uses `java.nio.file.Path` to canonicalize paths before use:

1. `Paths.get(DOCUMENT_STORE_DIR).toRealPath()` converts the base directory to an absolute canonical path, resolving any symlinks or relative references.
2. `baseDir.resolve(fileName).toRealPath()` resolves the user-supplied filename against the base directory and canonicalizes the result (following symlinks and resolving `.` and `..`). If the file does not exist, this throws IOException, which is caught and returns 404.
3. `requestedPath.startsWith(baseDir)` verifies the canonicalized path is still within the base directory using path-component-aware comparison, not string matching. This prevents escape attempts with sequences like `../`, absolute paths, or symlinks pointing outside the directory.
4. Only the validated path is passed to `FileInputStream`, eliminating the traversal risk.

If an attacker supplies `../../../etc/passwd`, the canonicalized result `/etc/passwd` fails the containment check and the request is rejected with 403 Forbidden. Legitimate requests for files within the directory (e.g., `readme.txt`) pass validation and proceed normally.

## Behaviour changes

1. **Added imports**: `java.nio.file.Path` and `java.nio.file.Paths` from the Java standard library (java.nio). No new external dependencies.

2. **Exception handling scope**: The try-catch block now wraps path canonicalization and validation, not just file I/O. Previously, file construction and existence checking happened outside exception handling. Now, `toRealPath()` exceptions (including file-not-found) are caught uniformly.

3. **New error response**: Requests with path traversal attempts now return 403 Forbidden (HTTP status) instead of falling through to the original file-exists check and potentially a 404 or 500 error.

4. **Removed explicit exists() check**: The original code at line 41-44 checked `requestedFile.exists()`. The fix relies on `toRealPath()` throwing IOException if the file does not exist, which is semantically equivalent but more atomic.

5. **Implicit behaviour on file-not-found**: All file-not-found scenarios (whether from `toRealPath()` or from the subsequent `FileInputStream`) now return 404 via the catch block, consolidating error handling. The original code explicitly checked existence first; the new code delegates to the file operation itself.

None of these behaviour changes violate the sink contract. File-based operations continue to read and transmit requested files as before. The changes only add security validation and consolidate error handling.
