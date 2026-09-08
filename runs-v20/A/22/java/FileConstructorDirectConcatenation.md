## Verdict

Confirmed. The `file` request parameter is concatenated directly into a filesystem path with no validation or containment check, allowing a caller to escape `DOCUMENT_STORE_DIR` using a traversal sequence (e.g. `../../etc/passwd`) or an absolute path.

## Source

`request.getParameter("file")` in `DocumentDownloadServlet.doGet` (line 32).

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

        File documentStoreDir = new File(DOCUMENT_STORE_DIR).getCanonicalFile();
        File requestedFile = new File(documentStoreDir, fileName).getCanonicalFile();

        if (!requestedFile.toPath().startsWith(documentStoreDir.toPath())) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid file parameter");
            return;
        }

        if (!requestedFile.exists()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Document not found");
            return;
        }

        response.setContentType("application/octet-stream");
        response.setHeader(
                "Content-Disposition",
                "attachment; filename=\"" + requestedFile.getName() + "\"");

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

The original code built the path with raw string concatenation (`DOCUMENT_STORE_DIR + File.separator + fileName`), so any `..` segments or an absolute path in `fileName` were passed straight to `File`/`FileInputStream` unchanged. A request such as `?file=../../../../etc/passwd` (or an absolute path on the server's OS) resolves outside the intended document store.

The fix resolves the requested file with `new File(documentStoreDir, fileName)` and then calls `getCanonicalFile()` on both the base directory and the resolved file. Canonicalization collapses `.`/`..` segments and symlinks, giving an absolute, normalized path. The result is then checked with `Path.startsWith()` against the canonical base directory: only a path that is actually contained within `DOCUMENT_STORE_DIR` is allowed through; anything that traverses out is rejected with `400 Bad Request` before the file is touched. This rejects the malicious input rather than trying to strip or sanitize it, which avoids the class of bugs where stripping a sequence like `../` still leaves an exploitable value behind.

The `Content-Disposition` header was also changed to use `requestedFile.getName()` (the canonicalized file's own base name) instead of echoing the raw `fileName` parameter, so a value like `x\r\nSet-Cookie: ...` or a path-containing name can no longer influence the response header either.
