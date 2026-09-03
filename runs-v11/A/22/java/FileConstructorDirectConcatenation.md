## Verdict

Path traversal vulnerability confirmed. User-supplied filename is concatenated directly into a File path without validation that the resolved path remains within the intended directory. An attacker can use path traversal sequences (e.g., `../../etc/passwd`) to access files outside the document store.

## Source

Line 39:
```java
File requestedFile = new File(DOCUMENT_STORE_DIR + File.separator + fileName);
```

The `fileName` parameter comes from untrusted user input (`request.getParameter("file")` at line 32) and is not validated before being used to construct the file path. The subsequent `exists()` check on line 41 does not prevent traversal — it only confirms that the resolved file exists, regardless of its location.

## Fix

Canonicalize both paths and validate that the resolved file is within the allowed directory:

```java
File requestedFile = new File(DOCUMENT_STORE_DIR + File.separator + fileName);
File baseDir = new File(DOCUMENT_STORE_DIR);

try {
    String basePath = baseDir.getCanonicalPath();
    String requestedPath = requestedFile.getCanonicalPath();
    
    if (!requestedPath.startsWith(basePath + File.separator) && 
        !requestedPath.equals(basePath)) {
        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
        return;
    }
} catch (IOException e) {
    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    return;
}

if (!requestedFile.exists()) {
    response.sendError(HttpServletResponse.SC_NOT_FOUND, "Document not found");
    return;
}
```

Alternatively, use `Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS)` to verify the path is not a symbolic link before proceeding.

## Explanation

Path traversal succeeds because no validation ensures the resolved file path stays within the base directory. The `getCanonicalPath()` method resolves `..` and `.` sequences and symbolic links to their absolute form, making traversal attempts visible. The startsWith check then verifies the canonical path begins with the base directory path (with a trailing separator to avoid prefix matching on partial directory names). This prevents accessing any file outside the intended directory, including symlink-based escapes. The fix must canonicalize before comparison; string prefix matching alone fails on symlinks and relative path constructions.
