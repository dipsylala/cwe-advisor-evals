## Verdict
exploitable

## Source
User-supplied filename from `request.getParameter("note")` at line 27, which is percent-decoded by the servlet container before reaching the application code.

## Sink
String comparison `canonicalPath.startsWith(BASE_DIR)` at line 37, which performs the containment check on the canonicalized path.

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

        if (!canonicalPath.startsWith(BASE_DIR + File.separator)) {
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
The original code used `canonicalPath.startsWith(BASE_DIR)` which is vulnerable to a sibling directory bypass: a path like `/app/uploads-secret/file.txt` passes the check because it starts with the string `/app/uploads`, even though it resides in a different directory. The fix appends `File.separator` to `BASE_DIR`, enforcing a path component boundary: the canonicalized path must start with `/app/uploads/` (with trailing separator), which prevents bypass via sibling directories. This aligns with the CWE-22 Java guidance that explicitly warns against string-based prefix checks without separators and recommends using either separator-terminated base strings or Path.startsWith(Path) comparisons.

## Behaviour changes
none
