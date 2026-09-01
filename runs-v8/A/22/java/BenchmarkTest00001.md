## Verdict
Path traversal vulnerability confirmed at line 73. User-controlled cookie value is URL-decoded but never validated to prevent directory traversal sequences (e.g., `../`) before being concatenated with a base directory and passed to `FileInputStream`.

## Source
Line 61: Cookie value extracted and URL-decoded without validation.
Line 71: User-supplied `param` concatenated with base directory `TESTFILES_DIR`.
Line 73: Unsanitized file path opened via `FileInputStream`.

The data flow: HTTP cookie → `URLDecoder.decode()` → string concatenation → `FileInputStream`.

## Fix
Replace lines 67-73 with:

```java
String fileName = null;
java.io.FileInputStream fis = null;

try {
    // Construct the intended file path
    java.io.File baseDir = new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR);
    java.io.File requestedFile = new java.io.File(baseDir, param);
    
    // Resolve to canonical paths and validate containment
    String baseDirCanonical = baseDir.getCanonicalPath();
    String requestedFileCanonical = requestedFile.getCanonicalPath();
    
    // Ensure the resolved file is within the base directory
    if (!requestedFileCanonical.startsWith(baseDirCanonical + java.io.File.separator) 
        && !requestedFileCanonical.equals(baseDirCanonical)) {
        throw new java.lang.SecurityException("Access denied: path traversal attempt");
    }
    
    fileName = requestedFileCanonical;
    fis = new java.io.FileInputStream(requestedFile);
```

## Explanation
The vulnerability allows an attacker to escape the intended directory by injecting path traversal sequences in the cookie value. For example, a cookie value of `../../../etc/passwd` would construct a path that accesses files outside the allowed directory.

The fix uses `File.getCanonicalPath()` to resolve symlinks and relative path components (`.` and `..`) to their true absolute paths. By verifying that the canonical path of the requested file is a child of (or equal to) the canonical base directory, path traversal attempts are blocked. Attempting to traverse outside the base directory will produce a canonical path that does not start with the base directory's path, causing the security check to reject it.
