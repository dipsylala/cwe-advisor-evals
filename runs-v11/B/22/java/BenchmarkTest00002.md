## Verdict

Exploitable

## Source

Line 61: `param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");`

The cookie value is decoded but not validated. An attacker can set a cookie with traversal sequences like `../../../etc/passwd`.

## Fix

**Vulnerable code (line 67-74):**

```java
String fileName = null;
java.io.FileOutputStream fos = null;

try {
    fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;

    // SAST FINDING: CWE-22 (Path Traversal) - a file path is built from request data and opened. Sink is the next statement.
    fos = new java.io.FileOutputStream(fileName, false);
```

**Fixed code:**

```java
String fileName = null;
java.io.FileOutputStream fos = null;

try {
    // Canonicalize the base directory
    java.nio.file.Path baseDir = java.nio.file.Paths.get(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR).toRealPath();
    
    // Reject invalid filenames (traversal sequences, path separators, null bytes)
    if (param == null || param.isEmpty() || param.contains("..") || param.contains("/") || param.contains("\\") || param.contains("\0")) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid filename");
        return;
    }
    
    // Resolve the path and normalize it
    java.nio.file.Path filePath = baseDir.resolve(param).normalize();
    
    // Verify containment using Path.startsWith()
    if (!filePath.startsWith(baseDir)) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid filename");
        return;
    }

    fileName = filePath.toString();
    // SAST FINDING: CWE-22 (Path Traversal) - path is now validated and safe
    fos = new java.io.FileOutputStream(filePath.toFile(), false);
```

## Explanation

The fix prevents path traversal by validating the user-supplied filename before constructing the file path. It canonicalizes the base directory using `Path.toRealPath()` to resolve symlinks and convert to absolute form. The supplied filename (`param`) is checked to ensure it contains no traversal sequences (`..`), path separators (`/`, `\`), or null bytes—ensuring it is a single filename component. The resolved path is then normalized and verified to stay within the base directory using `Path.startsWith()`, which performs path-component-aware comparison rather than string prefix matching. This prevents directory escape attacks while maintaining the original functionality of opening a file in the specified base directory.

## Behaviour changes

- **Added imports requirement:** `java.nio.file.Paths` and `java.nio.file.Path` are now required. These are standard Java 7+ library classes.
- **Changed error handling:** Invalid filenames now trigger an HTTP 400 (Bad Request) response instead of proceeding to attempt a file open that would fail or create unintended files. This is a safer failure mode.
- **Changed file path construction:** The path is now constructed via `Path.resolve()` and normalized rather than string concatenation. This provides robust path construction.
- **Changed return type in error case:** The method returns early on validation failure (line `return;` added), preventing subsequent file operations. This is a security improvement.
- **Changed return value to the response writer:** The output now reflects the canonicalized, validated path (`filePath.toString()`) instead of the raw user input, providing consistent and safe logging.

All changes directly address the path traversal vulnerability and maintain the original contract: attempting to open a file in the base directory. The fix does not alter the FileOutputStream exception handling or the overall try-catch structure.
