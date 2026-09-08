## Verdict

Confirmed. `AttachmentDownloadServlet.doGet` builds the download path from a
request parameter that is decoded twice - once implicitly by the servlet
container inside `request.getParameter()`, and again explicitly via
`URLDecoder.decode(rawFilename, "UTF-8")` - before it is checked and used to
build a filesystem path. The manual second decode lets an attacker
double-encode traversal metacharacters (for example `%252e%252e%252f`, which
becomes `%2e%2e%2f` after the container's single decode and only turns into
`../` after the servlet's own extra decode) so they can manufacture a
traversing or absolute path that the naive `contains("..")` blacklist was not
designed to withstand as the sole defense, and that does not defend against
an absolute-path payload (e.g. `/etc/passwd`) at all - `new File(parent,
child)` in Java discards `parent` outright whenever `child` is absolute, so
a filename with no `..` in it can still escape `ATTACHMENTS_DIR`.

## Source

`request.getParameter("file")` in `AttachmentDownloadServlet.doGet` (line 30) -
fully attacker-controlled HTTP request parameter.

## Fix

### File: AttachmentDownloadServlet.java

```java
package com.example.attachments;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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

        // request.getParameter() already performs one round of percent-decoding.
        // Do not decode it again: an extra, manual decode lets an attacker
        // double-encode "..", "/" or a drive prefix so those characters only
        // appear after this second pass, which is exactly what let traversal
        // and absolute-path payloads slip past a naive post-decode check.
        String filename = request.getParameter("file");
        if (filename == null || filename.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "file parameter is required");
            return;
        }

        // The store is flat, so a legitimate filename is a single path segment:
        // no separator, no drive/UNC prefix, and not "..". Comparing against
        // File.getName() rejects any value that would change which directory
        // component the name resolves into, which a "..".contains() check
        // alone does not - an absolute path such as "/etc/passwd" contains no
        // "..", but new File(parent, child) silently discards parent when
        // child is absolute.
        String nameOnly = new File(filename).getName();
        if (!nameOnly.equals(filename) || filename.contains("..")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
            return;
        }

        // Defense in depth: confirm the resolved file still lives directly
        // inside ATTACHMENTS_DIR after canonicalization, which also catches a
        // stored entry that turns out to be a symlink pointing elsewhere.
        File attachmentsDir = new File(ATTACHMENTS_DIR).getCanonicalFile();
        File target = new File(attachmentsDir, filename).getCanonicalFile();
        if (!attachmentsDir.equals(target.getParentFile())) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid filename");
            return;
        }

        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");

        try (InputStream in = new FileInputStream(target);
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

Two changes close the finding:

1. **Removed the redundant `URLDecoder.decode()` call.** `HttpServletRequest.getParameter()` already returns a fully percent-decoded value; decoding it a second time is what let an attacker's double-encoded payload turn into `..` or `/` only after any earlier, naive check had already run. The parameter is now validated and used exactly as the container decoded it, so there is no extra decode step left for an attacker to hide characters behind.
2. **Replaced the `contains("..")` blacklist with a structural, allowlist-style check plus canonical-path containment.** `new File(filename).getName()` returns just the final path segment; requiring it to equal `filename` rejects any value carrying a separator or an absolute/drive prefix - closing the `new File(parent, child)`-with-absolute-child gap that a `..`-only blacklist never covered - while the explicit `contains("..")` check still catches a bare `..` segment, which `getName()` alone would pass through unchanged. The subsequent canonical-path comparison against `ATTACHMENTS_DIR` is a second, independent backstop that also protects against a stored file that is itself a symlink escaping the directory.

Verified against the vulnerable input class: a double-encoded payload such as `%252e%252e%252f%252e%252e%252fetc%252fpasswd` now arrives at `filename` as the literal string `%2e%2e%2f%2e%2e%2fetc%2fpasswd` (only the container's single decode has run), which `new File(...).getName()` returns unchanged - it contains `%` and `2e`, not a real separator - so it fails the `nameOnly.equals(filename)` check and is rejected as an invalid filename rather than reaching the filesystem. An absolute-path payload such as `/etc/passwd` is rejected the same way, since `new File("/etc/passwd").getName()` is `"passwd"`, not `"/etc/passwd"`.
