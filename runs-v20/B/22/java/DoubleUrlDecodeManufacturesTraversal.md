## Verdict

Exploitable. Confidence: high.

- cwe_id: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'))
- location: `AttachmentDownloadServlet.java`, line 46 (`new File(ATTACHMENTS_DIR, filename)`), fed by the decode at line 38
- assumptions: none - the servlet, decode, validation, and sink are all present in the single file given

## Source

`request.getParameter("file")` (line 30). The servlet container has already percent-decoded the raw query/form value once by the time `getParameter` returns it, so the resulting `rawFilename` is plain text with respect to a single layer of encoding.

The code then calls `URLDecoder.decode(rawFilename, "UTF-8")` (line 38) - a second, explicit decode on top of the container's. An input that is percent-encoded twice on the wire (e.g. `%252e%252e%252f`) is decoded by the container into `%2e%2e%2f` (which contains no `..` substring and is inert against the line-40 check as it stood before this decode), and then decoded again by the explicit call into `../` - manufacturing the traversal sequence only after the point where the developer intended to have already normalized it. That decoded value flows unchanged into the `filename.contains("..")` check and then into `new File(ATTACHMENTS_DIR, filename)` at line 46, which is the sink: a `FileInputStream` is opened on the resulting `File` and streamed back to the client.

## Fix

### File: AttachmentDownloadServlet.java

```java
package com.example.attachments;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Serves previously-uploaded attachments back to the requesting user.
 *
 * The attachment store keeps every uploaded file flat under ATTACHMENTS_DIR,
 * named after the original filename supplied at upload time.
 */
public class AttachmentDownloadServlet extends HttpServlet {

    private static final String ATTACHMENTS_DIR = "/var/app-data/attachments";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // request.getParameter() has already been percent-decoded once by the
        // servlet container - use it as-is. Decoding it again would turn an
        // inert double-encoded literal (e.g. "%252e%252e%252f") into "../".
        String filename = request.getParameter("file");
        if (filename == null || filename.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "file parameter is required");
            return;
        }

        if (filename.indexOf('\0') >= 0 || Paths.get(filename).isAbsolute()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
            return;
        }

        Path baseDir = Paths.get(ATTACHMENTS_DIR).toRealPath();
        Path target;
        try {
            target = baseDir.resolve(filename).toRealPath();
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "attachment not found");
            return;
        }

        if (!target.startsWith(baseDir)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
            return;
        }

        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");

        try (InputStream in = Files.newInputStream(target);
             OutputStream out = response.getOutputStream()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
        }
    }
}
```

## Explanation

Two changes close the weakness. First, the redundant `URLDecoder.decode()` call is removed: `request.getParameter()` already returns the fully decoded value, and re-decoding it is exactly what let a double-encoded `..` sequence pass the blacklist check as an inert string and only turn into a real `../` afterward. Second, the string-based `contains("..")` blacklist is replaced with the canonicalize-then-contain pattern: the candidate path is resolved with `Path.resolve()` against the attachments directory and then both are canonicalized with `toRealPath()`, which follows symlinks and collapses any `.`/`..` components, and containment is verified with `Path.startsWith(Path)` rather than a string prefix test. `toRealPath()` is safe to use here (rather than only canonicalizing the parent) because this is a download of a file that must already exist; a target that does not resolve is treated as not found. An absolute filename and an embedded null byte are rejected before resolution, since `Path.resolve()` on an absolute argument discards the base path entirely and would otherwise bypass containment regardless of canonicalization. Together these mean no encoding depth or symlink trick can place the resolved file outside `ATTACHMENTS_DIR`, and legitimate filenames that happen to contain literal `..` (e.g. `notes..v2.txt`) are no longer rejected by a blacklist that is now redundant.

## Behaviour changes

- Removed the second `URLDecoder.decode()` call - required to close the weakness; the container's single decode is now the only decode applied, per the loaded guidance's explicit instruction not to re-decode a value the framework already decoded.
- Replaced the `filename.contains("..")` blacklist with canonicalization (`toRealPath()`) plus `Path.startsWith(Path)` containment - the blacklist could not catch traversal reached via a different total decode count or via a planted symlink; containment is the structural fix and the guidance says not to keep a substring test beside it.
- Added rejection of an absolute filename and a null byte before resolving - `java.nio.file.Path.resolve()` returns its argument unchanged when that argument is absolute, silently discarding the base directory; this check has no effect on any legitimate flat filename.
- Failure behaviour on a missing/unresolvable file changed from an unhandled `IOException` (previously thrown by `new FileInputStream(target)` and propagated to the container's default error handling, typically a 500) to an explicit `HttpServletResponse.SC_NOT_FOUND` (404). This follows directly from using `toRealPath()`, which throws when its target does not exist; the change is a deliberate, documented improvement in this fix, not an incidental one.
- Switched from `java.io.File`/`FileInputStream` to `java.nio.file.Path`/`Files.newInputStream()` - required so `toRealPath()` and `startsWith()` are available; the read loop, buffer size, and output stream handling are unchanged, so the response body a legitimate request receives is identical.
- `Content-Disposition` header construction (line originally `response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"")`) is unchanged and still uses the request-controlled filename; that is a pre-existing condition outside this CWE-22 finding's sink and was left as-is per the narrow scope of this fix.
- Verification: compiled with `javac` (JDK 26) against minimal stub `javax.servlet`/`javax.servlet.http` interfaces matching the signatures used (the real servlet API jar was not available in this environment) - compiled with zero errors and zero warnings.
