## Verdict

exploitable

- cwe_id: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory / Path Traversal)
- location: `DocumentDownloadServlet.java`, line 39 (sink: `new File(DOCUMENT_STORE_DIR + File.separator + fileName)`; the same taint reaches `new FileInputStream(requestedFile)` at line 50)
- confidence: high

## Source

`request.getParameter("file")` at line 32, read directly from the servlet request with no validation, encoding check, or allowlist before it is concatenated into a filesystem path. The value flows unchanged into the `File` constructor at line 39 and from there into `FileInputStream` at line 50 — a single straight-line method with no intervening sanitization, so the trace is direct: no encoding, canonicalization, or containment check exists anywhere on the path between source and sink.

## Fix

### File: DocumentDownloadServlet.java

```java
package com.example.docs;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
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

        Path baseDir = Paths.get(DOCUMENT_STORE_DIR).toRealPath();
        Path candidate;
        try {
            candidate = baseDir.resolve(fileName).normalize();
        } catch (InvalidPathException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid file parameter");
            return;
        }
        if (!candidate.startsWith(baseDir)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid file parameter");
            return;
        }
        if (!Files.exists(candidate)) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Document not found");
            return;
        }
        Path realFile = candidate.toRealPath();
        if (!realFile.startsWith(baseDir)) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Document not found");
            return;
        }
        File requestedFile = realFile.toFile();

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

The original code built a `File` by string-concatenating the untrusted `file` parameter directly onto the document store's base directory, so a value such as `../../etc/passwd` (or an absolute path, which `File`'s concatenation happily appends after the separator) escaped the intended directory with no check at all. The fix canonicalizes the base directory once with `Path.toRealPath()`, resolves the candidate under it and `normalize()`s the result, then rejects anything whose normalized form does not `startsWith` the canonical base — this catches `..` segments and absolute-path substitution textually, before the file is even known to exist. Because a symlink placed inside the store could still point outside it after normalization succeeds, the code re-canonicalizes the resolved candidate with a second `toRealPath()` (safe to call now that existence has been confirmed) and checks containment again against the real, symlink-resolved path. Only a path that passes both checks is turned into the `File` handed to `FileInputStream`, closing the traversal at the sink identified by the finding.

## Behaviour changes

- New 400 response ("Invalid file parameter") for a `file` value that resolves outside the document store directory (traversal or absolute-path attempt) or that contains characters `Path` rejects (e.g. a null byte) — this is the intended effect of the fix, not incidental.
- If `DOCUMENT_STORE_DIR` itself does not exist or is not resolvable at request time, `Paths.get(DOCUMENT_STORE_DIR).toRealPath()` throws `IOException`, which propagates out of `doGet` (declared on the method) instead of the original code's silent fall-through to a 404 "Document not found" from `requestedFile.exists()`. This only matters if the fixed base directory is ever missing/misconfigured, not for any value of the `file` parameter; it is a consequence of canonicalizing the base up front rather than a change made for its own sake.
- The `Content-Disposition` header still echoes the raw `fileName` parameter unchanged, exactly as the original code did — that reflection is outside this finding's sink (line 39) and was left untouched.
- Everything else — the missing-parameter check, the not-found response for a legitimate missing file, the content type, the streaming copy loop — is unchanged.

## Verification

Compiled with `javac` (JDK 26) against minimal stand-in classes for `javax.servlet`/`javax.servlet.http`/`javax.servlet.annotation` (the real servlet-api jar was not present in this environment) in an isolated scratch directory, separate from the case fixture. The fixed file compiled with zero errors and zero warnings, confirming all `java.nio.file` API usage (`Paths.get`, `Path.resolve`, `Path.normalize`, `Path.startsWith`, `Path.toRealPath`, `Files.exists`, `InvalidPathException`) is correctly typed and every import resolves. `Files`, `Path`, `Paths`, and `InvalidPathException` are all in the JDK standard library (`java.nio.file`), used exactly as documented in the loaded Java CWE-22 guidance.

Assumptions: no indirect-reference (ID-to-filename) mapping exists elsewhere in this single-file case, so the canonicalize-and-contain primary defence (the guidance's second option) was applied rather than the indirect-reference option, which would require application-level lookup infrastructure not present in the provided code.
