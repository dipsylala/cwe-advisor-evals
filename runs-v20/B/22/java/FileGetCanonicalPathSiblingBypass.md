## Verdict

CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) - **exploitable**. Confidence: high.

`UploadNotesServlet.doGet` (line 37) uses a raw string prefix test, `canonicalPath.startsWith(BASE_DIR)`, to confirm the resolved note path stays inside `/app/uploads`. `String.startsWith` has no concept of a path-component boundary, so a canonical path of `/app/uploads-secret/x` also satisfies `startsWith("/app/uploads")`. A request such as `note=../uploads-secret/x` (or any sibling directory name that shares the `/app/uploads` prefix, e.g. one created by an attacker with filesystem write access elsewhere, or an existing sibling directory on the host) resolves to a canonical path outside the intended root while passing the check, and is then opened and streamed back to the client.

## Source

- **Source:** `request.getParameter("note")` (line 27) - fully attacker-controlled, untrusted HTTP query/form parameter.
- **Flow:** `noteName` is concatenated onto `BASE_DIR` via `new File(BASE_DIR, noteName)` (line 33), resolved with `candidate.getCanonicalPath()` (line 34, this follows `..` segments and symlinks to an absolute string), then checked with the vulnerable string-prefix test (line 37).
- **Sink:** `new FileInputStream(noteFile)` (line 49), where `noteFile` is built directly from the unresolved-boundary `canonicalPath` (line 42) and streamed to the HTTP response.
- **Sink contract:** `getCanonicalPath()`/`getCanonicalFile()` return a fully resolved absolute path string/File and throw `IOException` on I/O failure (already declared on `doGet`); they do not require the target to exist, so a non-existent candidate still canonicalizes successfully and is later caught by the pre-existing `noteFile.isFile()` check. Nothing here is discarded or defaulted - the fix only replaces the containment comparison.

## Fix

### File: UploadNotesServlet.java

```java
package com.example.uploads;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Serves a note file previously uploaded by a user, looked up by the
 * relative filename the client supplies.
 */
public class UploadNotesServlet extends HttpServlet {

    // Application-wide directory that holds every user's uploaded notes.
    private static final String BASE_DIR = "/app/uploads";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String noteName = request.getParameter("note");
        if (noteName == null || noteName.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing 'note' parameter");
            return;
        }

        File baseDir = new File(BASE_DIR).getCanonicalFile();
        File candidate = new File(baseDir, noteName);
        File canonicalFile = candidate.getCanonicalFile();
        Path canonicalPath = canonicalFile.toPath();

        // Path-component-aware containment check: a raw string prefix test
        // (canonicalPath.startsWith(BASE_DIR)) accepts a sibling directory
        // such as /app/uploads-secret, since it never checks for a separator
        // boundary between the base directory and the rest of the path.
        if (!canonicalPath.startsWith(baseDir.toPath())) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access to the requested note is denied");
            return;
        }

        File noteFile = canonicalFile;
        if (!noteFile.isFile()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Note not found");
            return;
        }

        response.setContentType("text/plain");
        try (InputStream in = new FileInputStream(noteFile);
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

The fix replaces the string-prefix containment test with a path-component-aware comparison using `java.nio.file.Path.startsWith(Path)`, which only matches on whole path segments and therefore rejects a sibling such as `/app/uploads-secret` that a substring test would accept. `BASE_DIR` itself is also canonicalized (`new File(BASE_DIR).getCanonicalFile()`) before comparison, so the check compares two paths resolved the same way rather than a resolved candidate against a literal, unresolved constant - keeping the comparison correct even if `/app/uploads` itself were ever a symlink. The candidate is still built and canonicalized exactly as before (`new File(baseDir, noteName)` then `getCanonicalFile()`, which resolves `..` segments and symlinks without requiring the target to exist), so the existing `noteFile.isFile()` / 404 handling for a missing note is untouched. No new library is required; `java.nio.file.Path` is part of the JDK standard library (`java.nio.file`, available since Java 7).

## Behaviour changes

- The containment check now compares `Path` objects (`canonicalPath.startsWith(baseDir.toPath())`) instead of raw strings (`canonicalPath.startsWith(BASE_DIR)`). This is the fix itself: it closes the sibling-directory bypass (`/app/uploads-secret` no longer satisfies containment) while accepting exactly the same in-bounds paths as before.
- `BASE_DIR` is canonicalized once per request (`new File(BASE_DIR).getCanonicalFile()`) before being used as the comparison root and as the parent for `new File(baseDir, noteName)`. This does not change which files are reachable under normal deployment (`/app/uploads` with no symlinks in its own path resolves to itself); it only makes the containment check correct if any segment of `BASE_DIR` is ever a symlink.
- All other behaviour is unchanged: the 400/403/404 responses, the `noteFile.isFile()` existence check, the response content type, and the streaming logic are identical to the original.
- None of these changes alter the sink contract identified above: `getCanonicalFile()` still resolves without requiring existence, still throws `IOException` (already declared), and the missing-file path still falls through to the pre-existing `SC_NOT_FOUND` response.

**Verification:** Compiled with `javac` (JDK 26) against minimal stub definitions of `javax.servlet.ServletException`, `HttpServlet`, `HttpServletRequest`, and `HttpServletResponse` (the servlet-api types themselves are unchanged by this fix and were not available on the local classpath) - the fixed file compiled with no errors or warnings. Every new symbol (`java.nio.file.Path`, `File.getCanonicalFile()`, `File.toPath()`, `Path.startsWith(Path)`) is part of the JDK standard library and was confirmed present by this successful compilation.
