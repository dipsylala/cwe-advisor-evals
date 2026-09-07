## Verdict

VULNERABLE - confirmed path traversal due to string-based prefix check that is vulnerable to sibling directory bypass.

## Source

User-controlled filename from `request.getParameter("note")` at line 27, passed through `new File(BASE_DIR, noteName)` constructor without initial validation.

## Fix

Replace line 37's string-based `startsWith()` check with path-component-aware comparison using `java.nio.file.Path.startsWith(Path)`. Use `Path.toRealPath()` for proper canonicalization of both the base directory and candidate path.

### File: UploadNotesServlet.java

```java
package com.example.uploads;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;

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

        try {
            // Canonicalize both paths to absolute form with symlinks resolved
            Path basePath = Paths.get(BASE_DIR).toRealPath();
            Path candidatePath = Paths.get(BASE_DIR, noteName).toRealPath();

            // Enforce containment using path-component-aware comparison
            if (!candidatePath.startsWith(basePath)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access to the requested note is denied");
                return;
            }

            File noteFile = candidatePath.toFile();
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
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access to the requested note is denied");
        }
    }
}
```

## Explanation

The vulnerability exists in the original line 37: `if (!canonicalPath.startsWith(BASE_DIR))`. This uses string-based prefix comparison, which is vulnerable to sibling directory bypass—a canonical path like `/app/uploads_secret` would pass the check because the string starts with `/app/uploads`, even though it references a different directory.

The fix replaces this with Java NIO's path-component-aware comparison. By converting both paths to `java.nio.file.Path` objects and using `Path.startsWith(Path)`, the containment check now understands path boundaries. A sibling directory like `/app/uploads_secret` will correctly fail the check because `/app/uploads_secret` is not path-component-wise contained within `/app/uploads`.

The fix also uses `Path.toRealPath()` for both the base and candidate paths, which:
- Converts to absolute canonical form
- Resolves symbolic links
- Handles both existing and non-existing files appropriately (exceptions are caught and treated as access denied)

All IOException instances (including from `toRealPath()` when a path doesn't exist) are caught in a single handler, returning a 403 Forbidden error—the safe default when path validation fails.

## Behaviour changes

- Exception handling: Code now wraps the entire path validation and file access in a try-catch that returns 403 Forbidden on any IOException, making the code more defensive
- Path resolution: Now explicitly follows symlinks via `toRealPath()` rather than relying on `getCanonicalPath()`'s platform-specific behavior
- Non-existent files: If a requested file doesn't exist, `toRealPath()` throws IOException, caught and converted to 403 Forbidden (safe behavior)
- Imports: Added `java.nio.file.Path` and `java.nio.file.Paths` imports
