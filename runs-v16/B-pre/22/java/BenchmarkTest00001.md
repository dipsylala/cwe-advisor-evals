## Verdict

exploitable

## Source

Cookie value from the "BenchmarkTest00001" cookie (line 60-61: `theCookie.getValue()` passed to `URLDecoder.decode()`)

## Fix

**Vulnerable code (lines 57-73):**

```java
String param = "noCookieValueSupplied";
if (theCookies != null) {
    for (javax.servlet.http.Cookie theCookie : theCookies) {
        if (theCookie.getName().equals("BenchmarkTest00001")) {
            param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");  // VULNERABLE: extra decode
            break;
        }
    }
}

String fileName = null;
java.io.FileInputStream fis = null;

try {
    fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;  // VULNERABLE: no validation
    // SAST FINDING: CWE-22 (Path Traversal) - a file path is built from request data and opened. Sink is the next statement.
    fis = new java.io.FileInputStream(new java.io.File(fileName));
```

**Fixed code:**

```java
String param = "noCookieValueSupplied";
if (theCookies != null) {
    for (javax.servlet.http.Cookie theCookie : theCookies) {
        if (theCookie.getName().equals("BenchmarkTest00001")) {
            param = theCookie.getValue();  // Use value directly; container already decoded it
            break;
        }
    }
}

String fileName = null;
java.io.FileInputStream fis = null;

try {
    // Canonicalize the base directory and resolve requested path
    java.nio.file.Path baseDir = java.nio.file.Paths.get(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR).toRealPath();
    java.nio.file.Path resolvedPath = baseDir.resolve(param).toRealPath();
    
    // Verify the resolved path is within the base directory
    if (!resolvedPath.startsWith(baseDir)) {
        throw new java.io.IOException("Path traversal attempt detected");
    }
    
    fileName = resolvedPath.toString();
    fis = new java.io.FileInputStream(new java.io.File(fileName));
```

## Explanation

The vulnerability stems from two issues: (1) applying an extra `URLDecoder.decode()` to a cookie value that the servlet container has already decoded, which turns the inert literal `%2e%2e%2f` into the traversal sequence `../`; and (2) concatenating untrusted input directly with a base directory and opening the file without validating containment.

The fix removes the extra decode step and adds path canonicalization and containment validation. `Path.toRealPath()` resolves the path to its absolute canonical form, following symlinks. The `startsWith()` check on `Path` objects (not strings) ensures the resolved file is within the intended base directory, preventing `../` attacks and directory breakouts. If the path resolves outside the base, an exception is thrown and the file operation is rejected.

## Behaviour changes

- `URLDecoder.decode()` is removed: cookie values are no longer double-decoded. This prevents manufacturing of traversal sequences from percent-encoded literals and correctly handles legitimate filenames containing `+` (which URLDecoder maps to space).
- Path canonicalization with `toRealPath()` is added: the path is resolved to its real absolute form, and symlink chains are followed. This adds file I/O to confirm the target exists.
- Containment validation with `startsWith(Path)` is added: requests with paths outside the base directory now throw an `IOException` and the file is not opened. This may reject requests that previously succeeded if they attempted traversal.
- `fileName` is reassigned to the canonicalized path string: downstream code that logs or displays the filename will show the real canonical path, not the user-supplied one.
