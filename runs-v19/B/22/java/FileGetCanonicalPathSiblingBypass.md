## Verdict

VULNERABLE. The containment check on line 37 uses string-based prefix matching, which allows a sibling-directory bypass via symlinks. An attacker controlling a symlink in a sibling directory (e.g., `/app/uploads-backup` → `/etc`) can construct paths that pass the string prefix check but access files outside the intended directory.

## Source

Line 27: `request.getParameter("note")` - untrusted user input
Line 33: `new File(BASE_DIR, noteName)` - path constructed from user input
Line 34: `candidate.getCanonicalPath()` - canonicalization
Line 37: `if (!canonicalPath.startsWith(BASE_DIR))` - **vulnerable containment check**

## Fix

Use `java.nio.file.Path` objects with path-aware containment checking instead of string-based prefix matching. This respects directory boundaries and prevents sibling-directory bypass.

### File: UploadNotesServlet.java

```java
package com.example.uploads;

import java.io.File;
import java.io.FileInputStream;
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

        // Canonicalize paths using Path objects for proper containment checking
        Path baseDir = Paths.get(BASE_DIR).toRealPath();
        Path candidate = baseDir.resolve(noteName).toRealPath();

        // Use Path.startsWith(Path) for path-aware containment, not string comparison
        if (!candidate.startsWith(baseDir)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access to the requested note is denied");
            return;
        }

        File noteFile = candidate.toFile();
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

The original code used string-based prefix matching (`canonicalPath.startsWith(BASE_DIR)`), which is vulnerable to sibling-directory bypass. A symlink in a sibling directory (e.g., `/app/uploads-backup` → `/etc`) allows an attacker to construct paths like `../uploads-backup/passwd` that pass the string prefix check but access files outside the intended directory.

The fix replaces this with `java.nio.file.Path` objects using `Path.startsWith(Path)`, which performs path-aware containment checking that respects directory boundaries. The two key changes:

1. Line 34-35: Use `Paths.get()` and `toRealPath()` to canonicalize the base directory and candidate path as Path objects, following symlinks
2. Line 38: Use `candidate.startsWith(baseDir)` with Path objects instead of string comparison

`Path.startsWith()` correctly rejects sibling directories: a path `/app/uploads-backup/passwd` is not considered to start with the path `/app/uploads` because they are distinct directory components. The containment check now respects directory boundaries and prevents the sibling-directory bypass.

## Behaviour changes

- **Path representation**: Changed from `File` + String to `java.nio.file.Path` objects
- **Containment check**: Changed from string prefix matching to path-aware prefix matching using `Path.startsWith(Path)`
- **Canonical resolution**: Now explicitly canonicalizes the base directory via `toRealPath()`, ensuring consistent comparison
- **Return type conversion**: The canonical path is converted back to `File` via `toFile()` for compatibility with `FileInputStream`
- **No functional change to file serving**: The file is still located, checked for existence, and served in the same way; only the traversal protection is improved

