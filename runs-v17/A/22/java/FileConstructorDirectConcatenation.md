## Verdict
Path traversal vulnerability confirmed. User-supplied `fileName` parameter is concatenated directly into a file path without validation that the resulting path remains within the intended `DOCUMENT_STORE_DIR` directory. Attackers can use `../` sequences to escape the directory and access arbitrary files.

## Source
Line 39:
```
File requestedFile = new File(DOCUMENT_STORE_DIR + File.separator + fileName);
```

The `fileName` parameter originates from `request.getParameter("file")` at line 32 with only null and empty-string checks—no validation that the resolved path stays within `DOCUMENT_STORE_DIR`.

## Fix

### File: DocumentDownloadServlet.java

```java
package com.example.docs;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

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

        File documentStoreFile = new File(DOCUMENT_STORE_DIR);
        File requestedFile = new File(documentStoreFile, fileName);

        // Validate that the resolved file is within the document store directory
        String storePath = documentStoreFile.getCanonicalPath();
        String requestedPath = requestedFile.getCanonicalPath();

        if (!requestedPath.startsWith(storePath + File.separator)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
            return;
        }

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
    }
}
```

## Explanation
The fix adds a canonical path validation check before accessing the requested file:

1. **Canonicalization**: `getCanonicalPath()` resolves the file paths to their absolute, normalized form, eliminating `.` and `..` sequences and resolving symlinks. This reveals the true filesystem location.

2. **Directory boundary enforcement**: The check `requestedPath.startsWith(storePath + File.separator)` ensures the requested file is located under the document store directory. The `File.separator` suffix prevents a false positive if the store path is a prefix of a different directory (e.g., `/var/lib/appdata/document` would not match `/var/lib/appdata/document-store`).

3. **Rejection of out-of-bounds paths**: If the resolved path does not start with the store directory, the request is rejected with HTTP 403 Forbidden before any file access occurs.

This approach prevents path traversal attacks: requests like `file=../../etc/passwd` will have their canonical paths computed and rejected because the resulting path falls outside `DOCUMENT_STORE_DIR`.
