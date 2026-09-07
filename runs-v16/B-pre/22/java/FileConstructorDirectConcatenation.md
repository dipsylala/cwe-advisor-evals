## Verdict

**CONFIRMED** — Path traversal vulnerability at line 39.

The code concatenates user-supplied `fileName` directly into a file path without validation or canonicalization. An attacker can bypass the intended directory boundary using `../` sequences.

## Source

Line 32: `String fileName = request.getParameter("file");`

User input is obtained directly from the HTTP request parameter without restriction.

## Fix

**Vulnerable code (line 39):**
```java
File requestedFile = new File(DOCUMENT_STORE_DIR + File.separator + fileName);
```

**Fixed implementation (replaces lines 32–44):**

```java
String fileName = request.getParameter("file");
if (fileName == null || fileName.isEmpty()) {
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing file parameter");
    return;
}

// Reject traversal attempts
if (fileName.contains("..") || fileName.contains("/") || fileName.contains("\\") || fileName.startsWith(".")) {
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid filename");
    return;
}

try {
    // Validate and canonicalize paths
    java.nio.file.Path baseDir = java.nio.file.Paths.get(DOCUMENT_STORE_DIR).toRealPath();
    java.nio.file.Path requestedPath = baseDir.resolve(fileName);
    
    // File must exist before canonicalizing
    if (!java.nio.file.Files.exists(requestedPath)) {
        response.sendError(HttpServletResponse.SC_NOT_FOUND, "Document not found");
        return;
    }
    
    // Canonicalize the requested path (follows symlinks)
    java.nio.file.Path canonicalRequested = requestedPath.toRealPath();
    
    // Verify containment using path-component-aware comparison
    if (!canonicalRequested.startsWith(baseDir)) {
        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
        return;
    }
    
    File requestedFile = canonicalRequested.toFile();
    
    response.setContentType("application/octet-stream");
    response.setHeader("Content-Disposition", "attachment; filename=\"" + fileName + "\"");
    
    try (InputStream in = new FileInputStream(requestedFile);
            OutputStream out = response.getOutputStream()) {
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = in.read(buffer)) != -1) {
            out.write(buffer, 0, bytesRead);
        }
    }
} catch (IOException e) {
    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Server error");
    return;
}
```

**Required imports** (add to existing imports at the top of the file):
- `java.nio.file.Files`
- `java.nio.file.Path`
- `java.nio.file.Paths`

These are standard library classes.

## Explanation

The fix eliminates path traversal by enforcing that the resolved file must lie within the intended base directory.

**Key changes:**

1. **Traversal rejection**: Reject filenames containing `..`, path separators (`/`, `\`), or leading `.` before path resolution. This stops obvious attacks immediately.

2. **Canonicalization**: Convert both the base directory and requested path to absolute canonical form using `Path.toRealPath()`. This resolves relative path components (`.`, `..`) and symlinks to their true locations, defeating attempts to hide traversal in equivalent spellings.

3. **Containment check**: After canonicalization, verify the requested path is inside (or equals) the base using `Path.startsWith()`. This compares paths as components, not strings – so `/app/uploads-secret` correctly fails the check against `/app/uploads/` as a base.

4. **Existence check**: Verify the file exists before canonicalizing (since `toRealPath()` requires the target to exist). If it doesn't, return a 404 as before.

5. **Use canonical path for I/O**: Only after validation passes do we open the file for reading, using the canonical path to ensure the filesystem operation reads the validated target.

The fix preserves the servlet's existing contract: it still serves requested files from the document store, still validates file existence, and still rejects missing files with a 404.

## Behaviour changes

- **Stricter filename validation**: Filenames containing path separators or traversal sequences are rejected with a 400 error. Single-component filenames only (e.g., `document.pdf`, not `subdir/document.pdf`) are accepted.
- **New error conditions**: Access attempts that pass an allowlist check but resolve outside the base directory now return 403 Forbidden instead of serving the file. This is security-hardening and correct; it should not occur in normal usage.
- **New exception handling**: `IOException` from `toRealPath()` (e.g., permission denied, filesystem errors) returns 500 Internal Server Error. This is appropriate for server-side errors and helps distinguish them from missing-file 404s.
