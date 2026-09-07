## Verdict

FIXABLE. Path Traversal via unchecked user input in file path construction.

## Source

`fileName` parameter from `request.getParameter("file")` at line 32.

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

        Path baseDir;
        try {
            baseDir = Paths.get(DOCUMENT_STORE_DIR).toRealPath();
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Configuration error");
            return;
        }

        Path requestedPath;
        try {
            requestedPath = baseDir.resolve(fileName).toRealPath();
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Document not found");
            return;
        }

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
    }
}
```

## Explanation

The vulnerability existed because `fileName` was concatenated directly into the file path without validation, allowing attackers to use `../` sequences to escape the document directory and access arbitrary files.

The fix canonicalizes the path using `java.nio.file.Path.toRealPath()`, which resolves symlinks and relative path components (`.` and `..`) to an absolute canonical form. The resolved path is then verified to remain within the base directory using `Path.startsWith(Path)`, which performs path-component-aware comparison and rejects attempts to escape the directory. The method catches `IOException` during canonicalization to handle non-existent paths gracefully and returns a 404 error. For requests that escape the base directory, a 403 Forbidden response is returned instead of processing the traversal.

## Behaviour changes

- File paths are now restricted to the document store directory and its subdirectories
- Requests with traversal sequences or symlinks pointing outside the base directory are rejected
- Non-existent files return 404 instead of potentially traversing the filesystem
- Symlink escapes return 403 Forbidden instead of following the link
- The server's base directory path must exist and be readable; if not, a 500 error is returned
