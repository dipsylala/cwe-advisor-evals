## Verdict

Confirmed. The containment check at line 37 uses `String.startsWith(BASE_DIR)` on the canonicalized path, which is a raw prefix comparison rather than a path-boundary comparison. Because `BASE_DIR` ("/app/uploads") does not end in a separator, any sibling directory whose name simply extends that string as a prefix - for example `/app/uploads-public` or `/app/uploads2` - also starts with the literal string `"/app/uploads"` and passes the check even though it is outside the intended upload directory. A `note` value such as `../uploads-public/secret.txt` resolves (via `getCanonicalPath()`) to a path under that sibling directory and is served.

## Source

`request.getParameter("note")` at line 27 (`UploadNotesServlet.doGet`) - attacker-controlled HTTP query/form parameter, joined unvalidated into a `File` path and used to read and stream file contents back in the response.

## Fix

### File: UploadNotesServlet.java
```java
package com.example.uploads;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
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

        Path baseDir = Path.of(BASE_DIR).toRealPath();
        Path candidate = baseDir.resolve(noteName).normalize();

        if (!candidate.startsWith(baseDir)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access to the requested note is denied");
            return;
        }

        if (!Files.isRegularFile(candidate)) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Note not found");
            return;
        }

        response.setContentType("text/plain");
        try (InputStream in = Files.newInputStream(candidate);
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

The vulnerability is a string-prefix containment check, not a missing canonicalization step - the code already canonicalized the path. `startsWith(String)` on the canonical path string treats `/app/uploads` and `/app/uploads-public` as sharing a prefix, so it does not enforce a directory boundary; only a check that respects path segment boundaries does.

The fix replaces the `File`/`String` containment test with `java.nio.file.Path.startsWith(Path)`, which compares path components rather than raw characters, so `/app/uploads-public/secret.txt` no longer satisfies containment in `/app/uploads`. The base directory is resolved once via `toRealPath()` (equivalent to the original `getCanonicalPath()`, resolving symlinks and `..` segments), and the candidate is built with `resolve(noteName).normalize()` before the containment check, so traversal sequences in `noteName` are collapsed prior to the comparison rather than compared against as a substring. The subsequent existence check and file read were switched to the `java.nio.file.Files` equivalents operating on the same validated `Path`, preserving the original 400/403/404 behavior and streaming logic without introducing a second, divergent path resolution.
