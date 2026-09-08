## Verdict

Confirmed CWE-22 path traversal vulnerability via sibling directory bypass.

## Source

The vulnerability is at line 37 in the path containment check:

```java
if (!canonicalPath.startsWith(BASE_DIR)) {
```

This check fails to account for sibling directories. A directory named `/app/uploads-evil` would pass the `startsWith(BASE_DIR)` check when `BASE_DIR = "/app/uploads"`, even though it is not contained within the uploads directory. An attacker can exploit this to access files outside the intended directory.

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
        if (!canonicalPath.equals(BASE_DIR) && !canonicalPath.startsWith(BASE_DIR + File.separator)) {
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

The fix modifies line 37 to properly validate path containment by checking that the canonical path either:

1. Equals the base directory exactly, OR
2. Starts with the base directory followed by a path separator

The updated condition:
```java
!canonicalPath.equals(BASE_DIR) && !canonicalPath.startsWith(BASE_DIR + File.separator)
```

This prevents the sibling directory bypass where a path like `/app/uploads-evil/file` would incorrectly pass a simple string prefix check. By requiring the path separator after the base directory, we ensure the resolved file is actually contained within the intended directory and not in a sibling or adjacent directory with a similar name.
