## Verdict

Real issue. The `fileName` parameter from user input is concatenated directly into a file path without validation, allowing path traversal attacks to read files outside the intended directory.

## Source

`request.getParameter("file")` at line 32 provides untrusted filename input. This value flows directly into path construction at line 39 without any traversal validation.

Data flow: HTTP request parameter → string concatenation with base directory → `File` constructor (sink) → `FileInputStream` for file access.

An attacker supplying `../../../etc/passwd` or similar sequences escapes `DOCUMENT_STORE_DIR` and accesses arbitrary files readable by the servlet process.

## Fix

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

        // Reject traversal sequences, absolute paths, and null bytes
        if (fileName.contains("../") || fileName.contains("..\\") || 
            fileName.startsWith("/") || fileName.startsWith("\\") ||
            fileName.contains("\0")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid file name");
            return;
        }

        try {
            // Canonicalize paths and verify containment
            Path basePath = Paths.get(DOCUMENT_STORE_DIR).toRealPath();
            Path requestedPath = basePath.resolve(fileName).toRealPath();

            // Verify the resolved path is within the base directory
            if (!requestedPath.startsWith(basePath)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
                return;
            }

            // Convert to File and proceed with download
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

The fix adds three layers of defence aligned with CWE-22 guidance: **reject**, **canonicalize**, and **contain**.

**Reject:** Before any path operations, the code explicitly rejects filenames containing traversal sequences (`../`, `..\`), absolute paths (leading `/` or `\`), and null bytes. This provides early rejection of obvious attack attempts.

**Canonicalize:** `Path.toRealPath()` on both the base directory and the resolved path normalizes each to its absolute canonical form, resolving all symlinks and relative-path components (`.`, `..`). This prevents attackers from using unicode normalization or other encoding tricks to hide traversal.

**Contain:** After canonicalization, `Path.startsWith()` (a component-aware path comparison, not a string prefix check) verifies the resolved file is within the base directory. This is the primary control that prevents traversal even if the reject layer is bypassed.

The fix wraps the entire operation in a try-catch that treats `IOException` from `toRealPath()` (raised when a path component does not exist) as "file not found," preserving the original error response semantics while closing the traversal window.

## Behaviour changes

- Input validation now returns HTTP 400 (Bad Request) for traversal attempts instead of silently attempting to construct the path.
- The check for file existence is now implicit in `toRealPath()`, which raises `IOException` if the resolved path does not exist, caught and reported as HTTP 404 (Not Found) instead of the explicit `exists()` call.
- Symlinked files are now followed and validated for containment. A symlink to a file outside the base directory is rejected with HTTP 403 (Forbidden) instead of being served.
- Error responses are now more granular: 400 for bad input, 403 for access denied (path escapes base), 404 for file not found, instead of all errors reporting 404.
