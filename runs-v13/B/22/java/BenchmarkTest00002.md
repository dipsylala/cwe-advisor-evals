## Verdict

Exploitable

## Source

Line 55-61: Cookie value extracted from `request.getCookies()`, retrieved via `theCookie.getValue()`. The critical flaw is line 61: `param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");` applies a second decode operation to a value already decoded by the servlet container, enabling an attacker to smuggle traversal sequences (e.g., `%2e%2e%2f` becomes `../` after double-decoding).

## Sink

Line 74: `fos = new java.io.FileOutputStream(fileName, false);`

The `fileName` parameter at line 71 is constructed as `org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param` with no validation that the path remains within the base directory. An attacker can use `../` sequences or symlinks to write files outside the intended directory.

## Fix

**Vulnerable code (line 55-74):**
```java
javax.servlet.http.Cookie[] theCookies = request.getCookies();

String param = "noCookieValueSupplied";
if (theCookies != null) {
    for (javax.servlet.http.Cookie theCookie : theCookies) {
        if (theCookie.getName().equals("BenchmarkTest00002")) {
            param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");  // PROBLEM: double-decode
            break;
        }
    }
}

String fileName = null;
java.io.FileOutputStream fos = null;

try {
    fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;  // PROBLEM: no validation
    fos = new java.io.FileOutputStream(fileName, false);  // SINK: path not verified
```

**Fixed code:**
```java
javax.servlet.http.Cookie[] theCookies = request.getCookies();

String param = "noCookieValueSupplied";
if (theCookies != null) {
    for (javax.servlet.http.Cookie theCookie : theCookies) {
        if (theCookie.getName().equals("BenchmarkTest00002")) {
            param = theCookie.getValue();  // Don't double-decode - servlet already decoded it
            break;
        }
    }
}

String fileName = null;
java.io.FileOutputStream fos = null;

try {
    java.nio.file.Path basePath = new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR).toPath().toRealPath();
    
    // Validate that param is a single filename component (no directory separators or traversal)
    java.nio.file.Path singleFileName = java.nio.file.Paths.get(param);
    if (!singleFileName.getFileName().toString().equals(param)) {
        throw new SecurityException("Invalid filename: contains directory separators or traversal sequences");
    }
    
    // Construct the full path and verify it stays within the base directory
    java.nio.file.Path filePath = basePath.resolve(param);
    if (!filePath.getParent().equals(basePath)) {
        throw new SecurityException("Path traversal blocked: filename would escape base directory");
    }
    
    fileName = filePath.toString();
    fos = new java.io.FileOutputStream(fileName, false);  // SINK: now safe
```

## Explanation

The original code constructs a file path from cookie data without any traversal control. The primary vulnerabilities are:

1. **Double-decoding**: `URLDecoder.decode()` is applied to a cookie value that the servlet container has already decoded, transforming inert percent-encoded sequences like `%2e%2e%2f` into the traversal sequence `../`.

2. **No path containment validation**: The path is built by simple string concatenation with no check that it remains within the intended base directory.

The fix eliminates both weaknesses. First, it removes the `URLDecoder.decode()` call to use the already-decoded cookie value directly. Second, it validates the filename before use: it must be a single path component (no directory separators or relative path references like `..` or `.`), verified by comparing `Paths.get(param).getFileName().toString()` against the original value. Third, it constructs the path using `Path.resolve()` and confirms that the resulting file's parent directory equals the canonical base directory, ensuring the file is created directly in the base with no traversal possible.

The validation rejects the path as a `SecurityException` rather than silently stripping traversal characters, preserving visibility of attack attempts in logs and error handling.

## Behaviour changes

- The cookie value is no longer double-decoded: `param` receives the servlet-decoded value without an additional `URLDecoder.decode()` pass. This prevents transformation of inert percent-encoded traversal sequences into live `../` sequences.
- A `SecurityException` is raised instead of silently opening a file if `param` contains directory separators, relative path components, or evaluates to anything other than a single filename. The original code would proceed silently, creating files outside the base directory.
- The filename is restricted to single path components (no `/`, `\`, `..`, or `.`). Filenames matching these patterns are now rejected; the original code would accept them.
- A canonical base directory path (`basePath.toRealPath()`) is computed once and used for containment verification. This ensures symlink-following and establishes an authoritative root; the original used a string constant without resolving it.
- An additional runtime check (`filePath.getParent().equals(basePath)`) verifies that the resolved path's parent is exactly the base directory, providing defence-in-depth against symlink-based escape attempts.
