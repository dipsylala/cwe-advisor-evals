## Verdict

The finding is real. User input from `request.getParameter("file")` flows directly into a File constructor without validation, allowing path traversal attacks (e.g., `../../etc/passwd`).

## Source

Line 32: `String fileName = request.getParameter("file")` — attacker-controlled input from HTTP request parameter.

## Fix

The vulnerable code directly concatenates user input into the file path without validation:
```java
File requestedFile = new File(DOCUMENT_STORE_DIR + File.separator + fileName);
```

Replace string concatenation with canonicalization and containment verification using `java.nio.file.Path`:

1. Canonicalize the base directory with `toRealPath()` to resolve symlinks and produce an absolute path.
2. Resolve the user-supplied filename against the base and canonicalize it.
3. Verify the canonical path starts with the canonical base using `Path.startsWith(Path)`.
4. Convert back to `File` for use with existing `FileInputStream`.

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

        // Canonicalize base directory
        Path basePath;
        try {
            basePath = Paths.get(DOCUMENT_STORE_DIR).toRealPath();
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Server configuration error");
            return;
        }

        // Canonicalize and validate the requested file path
        Path requestedPath;
        try {
            requestedPath = basePath.resolve(fileName).toRealPath();
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Document not found");
            return;
        }

        // Verify the resolved path is within the base directory
        if (!requestedPath.startsWith(basePath)) {
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

The fix replaces string concatenation with `java.nio.file.Path` canonicalization and containment verification. `toRealPath()` resolves symlinks, relative path components (`..`, `.`), and converts to absolute form. By calling `toRealPath()` on both the base directory and the resolved requested path, and then verifying the requested path `startsWith(basePath)`, the fix closes the path traversal vector. Any attempt to use `../` sequences or symlink tricks to escape the document store will either be resolved to a path outside the base (and rejected) or fail during canonicalization (e.g., if a symlink loop exists). The `File` object is created only after verification passes, ensuring `FileInputStream` on line 50 (now line 59 after additions) operates on a validated path.

## Behaviour changes

- **New imports**: Added `java.nio.file.Path` and `java.nio.file.Paths` for path canonicalization.
- **Path resolution error handling**: `toRealPath()` throws `IOException` if the file doesn't exist or access is denied; this is caught and reported as SC_NOT_FOUND (previously the code would have created a File object for a non-existent path and checked with `.exists()` afterward).
- **Containment verification**: The new `startsWith()` check ensures paths outside the base directory are rejected with SC_FORBIDDEN; previously, arbitrary paths would be accepted.
- **Symlink handling**: `toRealPath()` follows symlinks by default, so planted symlinks outside the base will be detected and rejected.
- **Null bytes**: Not explicitly checked; `toRealPath()` and the filesystem will reject null bytes if encountered during path resolution.
