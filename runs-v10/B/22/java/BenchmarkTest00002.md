## Verdict

Confirmed CWE-22 Path Traversal vulnerability. User-controlled cookie data (`param`) is concatenated with a base directory and passed to `FileOutputStream` without validation, allowing directory traversal via `../` sequences.

## Source

**Line 61** (indirect): `param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");`

The `param` variable receives untrusted cookie data.

**Line 71**: `fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;`

Unsafe path construction via string concatenation. No validation that the resulting path stays within `TESTFILES_DIR`.

**Line 74** (sink): `fos = new java.io.FileOutputStream(fileName, false);`

Untrusted path reaches the file operation. An attacker can use `../` sequences in the cookie to traverse to parent directories and write arbitrary files.

## Fix

Replace lines 70-78 with:

```java
try {
    // Validate param to prevent path traversal
    java.nio.file.Path basePath = java.nio.file.Paths.get(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR).toRealPath();
    
    // Reject absolute paths and paths with separators or traversal sequences
    if (java.nio.file.Paths.get(param).isAbsolute() ||
        param.contains("..") || 
        param.contains("/") || 
        param.contains("\\")) {
        throw new java.io.IOException("Invalid filename: path traversal attempt");
    }
    
    java.nio.file.Path requestedPath = basePath.resolve(param);
    java.nio.file.Path parentPath = requestedPath.getParent();
    
    // Verify parent directory is within the base directory
    if (parentPath == null || !parentPath.toRealPath().startsWith(basePath)) {
        throw new java.io.IOException("Path traversal not allowed");
    }
    
    fos = new java.io.FileOutputStream(requestedPath.toFile(), false);
    response.getWriter()
            .println(
                    "Now ready to write to file: "
                            + org.owasp.esapi.ESAPI.encoder().encodeForHTML(requestedPath.toString()));

} catch (Exception e) {
```

## Explanation

The fix follows three key principles from CWE-22 remediation:

1. **Path object isolation**: Replace string concatenation (`TESTFILES_DIR + param`) with `Path.resolve()`, which is path-aware and prevents absolute-path injection.

2. **Input validation**: Reject `param` values that are absolute paths, contain path separators (`/` or `\`), or contain traversal sequences (`..`). This prevents the most common attack vectors before path construction.

3. **Canonicalization and containment check**: Use `toRealPath()` on the parent directory to canonicalize and resolve symlinks, then verify the result is within `basePath` using `Path.startsWith(Path)`. This prevents both `../` traversal and symlink-based escapes. For write operations, check the parent directory (which must exist) rather than the target file (which may not).

The `Path.startsWith()` comparison is component-aware and prevents false positives from sibling directories like `/app/uploads-secret` passing a string prefix check of `/app/uploads`.

## Behaviour changes

- **Input rejection**: Filenames containing path separators, `..`, or absolute paths are now rejected with an IOException instead of being passed to FileOutputStream.
- **Path validation**: All file paths are now canonicalized and verified to stay within the base directory before being opened.
- **Exception handling**: Invalid paths throw an IOException that is caught by the existing exception handler (line 80), which logs the filename to stderr and continues - same as the original error flow.
- **No functional regression**: Legitimate filenames (single components without separators or dots) pass through and function identically to the original code.
