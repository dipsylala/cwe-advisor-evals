## Verdict

Exploitable. An attacker can supply a cookie value containing path traversal sequences (e.g., `../../../etc/passwd`) to read arbitrary files on the system outside the intended directory.

## Source

The untrusted data originates from an HTTP cookie value retrieved at line 55:
```java
javax.servlet.http.Cookie[] theCookies = request.getCookies();
```

The cookie value is extracted and URL-decoded at line 61:
```java
param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
```

This URL-decoded `param` is directly concatenated with a base directory path at line 71 with no validation of path traversal sequences.

## Fix

**Vulnerable code (line 70-73):**
```java
try {
    fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;
    // SAST FINDING: CWE-22 (Path Traversal) - a file path is built from request data and opened. Sink is the next statement.
    fis = new java.io.FileInputStream(new java.io.File(fileName));
```

**Fixed code:**
```java
try {
    // Canonicalize the base directory and resolve the user-supplied filename relative to it
    java.nio.file.Path baseDir = java.nio.file.Paths.get(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR).toRealPath();
    java.nio.file.Path filePath = baseDir.resolve(param).toRealPath();
    
    // Verify the resolved path stays within the base directory (prevents path traversal)
    if (!filePath.startsWith(baseDir)) {
        throw new java.io.IOException("Path traversal detected: file outside allowed directory");
    }
    
    fileName = filePath.toString();
    fis = new java.io.FileInputStream(filePath.toFile());
```

## Explanation

The fix eliminates the path traversal vulnerability by canonicalizing both the base directory and the resolved file path using `toRealPath()`, which follows symlinks and resolves `.` and `..` to their true locations. The critical security check compares the canonicalized paths using `Path.startsWith(Path)` to verify the final resolved path remains within the intended base directory. This prevents attackers from using sequences like `../` to escape the directory. The path comparison is done on `Path` objects rather than strings, avoiding the bypass where a string prefix check like `.startsWith("/app/uploads")` would incorrectly allow `/app/uploads-secret`. If canonicalization shows the path has escaped the base directory, an `IOException` is thrown immediately before attempting the file open. The `fileName` variable is populated from the validated path and used for logging/output, so only the canonicalized, containment-verified path reaches the `FileInputStream` sink.

## Behaviour changes

**Exception handling:** The fix may throw `IOException` during `toRealPath()` if the file does not exist, or if the path traversal check fails. The original code would also throw `FileNotFoundException` (a subtype of `IOException`) if the file doesn't exist when constructing `FileInputStream`, so the exception type and behavior are consistent with the original contract. A path traversal attempt now throws explicitly before attempting the file open rather than potentially succeeding in accessing an unauthorized file. The catch block at line 86 handles both scenarios identically.

**Path resolution:** Symbolic links are now resolved to their canonical targets. If `baseDir` contains a symlink, `toRealPath()` follows it. If an attacker attempts to use a symlink within the file parameter to escape the directory, the canonicalization will reveal the true target and the `startsWith()` check will catch it.

**None.** The fix preserves the sink contract: it still produces a `FileInputStream` on success and throws `IOException` on error, with identical retry and resource cleanup semantics.
