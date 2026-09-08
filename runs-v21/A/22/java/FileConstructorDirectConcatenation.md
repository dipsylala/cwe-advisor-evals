## Verdict

The code is vulnerable to path traversal (CWE-22). The `fileName` parameter from the HTTP request is concatenated directly into the file path without validation that it stays within the intended directory. An attacker can provide values like `../../../etc/passwd` to read arbitrary files on the system.

## Source

The vulnerability exists in `DocumentDownloadServlet.java` at line 39:

```java
File requestedFile = new File(DOCUMENT_STORE_DIR + File.separator + fileName);
```

The `fileName` comes from `request.getParameter("file")` (line 32) and is not validated before being used in the path concatenation. The code does check if the file exists, but does not verify that the resolved path remains within the base directory.

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

        // Resolve the requested file path and verify it stays within the base directory
        Path basePath = Paths.get(DOCUMENT_STORE_DIR).toAbsolutePath();
        Path requestedPath = basePath.resolve(fileName).normalize();

        // Reject any path that attempts to escape the base directory
        if (!requestedPath.startsWith(basePath)) {
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
    }
}
```

## Explanation

The fix adds path traversal validation using `java.nio.file.Path`:

1. **Imports**: Added `java.nio.file.Path` and `java.nio.file.Paths` to the imports.

2. **Path Resolution**: 
   - `Paths.get(DOCUMENT_STORE_DIR).toAbsolutePath()` gets the absolute, canonical base directory path
   - `basePath.resolve(fileName).normalize()` resolves the user-supplied filename relative to the base and normalizes it to remove `..` and `.` segments

3. **Validation**: 
   - `requestedPath.startsWith(basePath)` ensures the resolved path stays within the intended directory
   - Any attempt to escape via `../` sequences is rejected since `normalize()` resolves them before the `startsWith()` check

4. **Error Handling**: 
   - Returns HTTP 403 Forbidden if the path escapes the base directory, preventing the attacker from accessing restricted files

This approach prevents path traversal attacks while preserving legitimate file access within the intended directory.
