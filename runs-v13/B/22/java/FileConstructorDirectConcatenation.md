## Verdict

Confirmed path traversal vulnerability. The `fileName` parameter from the HTTP request is concatenated directly into a file path without validation. An attacker can use `../` sequences to escape the intended directory.

## Source

Line 32-39 in DocumentDownloadServlet.java:

```
String fileName = request.getParameter("file");  // Untrusted source
if (fileName == null || fileName.isEmpty()) {
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing file parameter");
    return;
}

File requestedFile = new File(DOCUMENT_STORE_DIR + File.separator + fileName);  // Vulnerable sink
```

The `fileName` parameter is attacker-controlled. It reaches the File constructor without canonicalization or containment validation, allowing path traversal attacks.

## Fix

Replace the vulnerable path construction (lines 38-39) with canonical path resolution and containment verification:

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
            // Canonicalize the base directory
            Path baseDir = Paths.get(DOCUMENT_STORE_DIR).toRealPath();
            
            // Construct and canonicalize the candidate path
            Path candidatePath = baseDir.resolve(fileName);
            Path requestedPath = candidatePath.toRealPath();
            
            // Verify the resolved path is within the base directory
            if (!requestedPath.startsWith(baseDir)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
                return;
            }
            
            File requestedFile = requestedPath.toFile();
            
            if (!requestedFile.exists()) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "Document not found");
                return;
            }

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

The fix uses Java's `java.nio.file.Path` API to enforce secure path handling:

1. **Canonicalization**: `baseDir.toRealPath()` and `candidatePath.toRealPath()` resolve both paths to their canonical absolute form, following symlinks and eliminating `..` sequences.

2. **Containment verification**: `requestedPath.startsWith(baseDir)` uses path-component-aware comparison to ensure the resolved file stays within the intended directory. String prefix matching would be unsafe (e.g., `/app/uploads-secret` would pass a `startsWith("/app/uploads")` string test).

3. **Method safety**: `Path.toRealPath()` follows symbolic links and validates that paths resolve to real files, preventing symlink attacks. It throws `IOException` if the path does not exist, which is caught and reported as "Document not found" to maintain the original error behavior.

4. **Error handling**: Path resolution failures (including non-existent files) are caught and handled gracefully, maintaining the existing user experience while preventing the vulnerability.

The fix preserves the original behavior: files must exist and must be within the document store directory. Attempts to traverse outside the directory are rejected with a 403 Forbidden response.

## Behaviour changes

- **Additional imports**: Added `java.nio.file.Path` and `java.nio.file.Paths` to support canonical path operations.
- **New IOException handling**: The entire file resolution logic is wrapped in a try-catch block to handle path resolution failures, which now serves as the point for both missing files and path traversal attempts.
- **Access control change**: Requests attempting to access files outside the permitted directory now receive a 403 Forbidden response instead of silently succeeding (which would be the vulnerable behavior).
- **Symlink handling**: The fix now follows symbolic links via `toRealPath()`, which matches Java best practice and prevents symlink-based escape attempts.
- **No functional change for valid requests**: Legitimate file downloads within the document store continue to work identically.
