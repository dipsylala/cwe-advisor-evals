## Verdict

Path traversal vulnerability confirmed and remediated. The original code uses string-based path prefix comparison without a path separator, allowing sibling directories to bypass the containment check (e.g., `/app/uploads-backup` passes a check for `/app/uploads`).

## Source

- **CWE**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **File**: UploadNotesServlet.java
- **Vulnerable code location**: Line 37
- **Untrusted source**: `request.getParameter("note")` (line 27) supplies the user-controlled `noteName` parameter
- **Data flow**: noteName → File constructor (line 33) → getCanonicalPath() (line 34) → vulnerable string.startsWith() check (line 37)
- **Sink**: The `startsWith()` comparison without proper path component awareness (line 37)

## Fix

### File: UploadNotesServlet.java

```java
package com.example.uploads;

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

        File candidate = new File(BASE_DIR, noteName);
        String canonicalPath = candidate.getCanonicalPath();

        // SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
        String baseDirWithSeparator = BASE_DIR + File.separator;
        if (!canonicalPath.startsWith(baseDirWithSeparator)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access to the requested note is denied");
            return;
        }

        File noteFile = new File(canonicalPath);
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

The vulnerability exploits a flaw in string-based pathname comparison. The original code checked if the canonical path started with the base directory string (`/app/uploads`), but this does not enforce directory boundaries. A sibling directory like `/app/uploads-backup` passes the check because its string representation starts with `/app/uploads`.

The fix appends `File.separator` (the platform-specific directory separator, `/` on Unix) to the base directory before comparison, ensuring that only paths actually contained within the base directory are accepted. This enforces path component awareness: `/app/uploads-backup/file.txt` no longer passes because it does not start with `/app/uploads/`, while legitimate files like `/app/uploads/file.txt` continue to pass.

The code already canonicalizes the path using `getCanonicalPath()`, which resolves symbolic links and normalizes relative references like `..` before validation. The fix ensures this canonicalized path is validated correctly against a separator-terminated base directory, following the Java guidance for path traversal prevention in the cwe-advisor knowledge base.

## Behaviour changes

- **Before**: Paths to sibling directories (e.g., `/app/uploads-backup/notes/secret.txt`) passed the containment check and could be accessed.
- **After**: Only paths that start with `/app/uploads/` are accepted. Sibling directories and paths outside the intended directory are correctly rejected with an HTTP 403 Forbidden response.
- **Legitimate files**: Files within `/app/uploads/` continue to be served normally. No change in behavior for authorized access.
- **Error handling**: Requests for files outside the base directory or non-existent files return appropriate HTTP error codes (403 Forbidden for traversal attempts, 404 Not Found for missing files).
