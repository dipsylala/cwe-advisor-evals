## Verdict

Exploitable. An attacker-controlled cookie value reaches a file open operation without validation, allowing path traversal via `../` sequences to read arbitrary files.

## Source

Line 61: Cookie value is extracted from `request.getCookies()` and unnecessarily URL-decoded a second time:
```java
param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
```

The servlet container already percent-decodes cookie values. This second `URLDecoder.decode()` call reinterprets literal sequences: `%2e%2e%2f` becomes `../`, enabling path traversal.

Line 71: The untrusted parameter is concatenated directly into a file path:
```java
fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;
```

## Fix

Remove the unnecessary second URL decoding. Canonicalize the resolved path using `java.nio.file.Path.toRealPath()` and enforce containment within the base directory using `Path.startsWith()` before opening the file.

**Vulnerable code (lines 57–73):**
```java
String param = "noCookieValueSupplied";
if (theCookies != null) {
    for (javax.servlet.http.Cookie theCookie : theCookies) {
        if (theCookie.getName().equals("BenchmarkTest00001")) {
            param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
            break;
        }
    }
}

String fileName = null;
java.io.FileInputStream fis = null;

try {
    fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;
    // SAST FINDING: CWE-22 (Path Traversal) - a file path is built from request data and opened. Sink is the next statement.
    fis = new java.io.FileInputStream(new java.io.File(fileName));
```

**Fixed code:**
```java
String param = "noCookieValueSupplied";
if (theCookies != null) {
    for (javax.servlet.http.Cookie theCookie : theCookies) {
        if (theCookie.getName().equals("BenchmarkTest00001")) {
            param = theCookie.getValue();  // Already percent-decoded by servlet container
            break;
        }
    }
}

String fileName = null;
java.io.FileInputStream fis = null;

try {
    // Canonicalize the base directory and construct the candidate path
    java.nio.file.Path baseDir = java.nio.file.Paths.get(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR).toRealPath();
    java.nio.file.Path resolvedPath = baseDir.resolve(param).toRealPath();
    
    // Enforce containment: reject paths outside the base directory
    if (!resolvedPath.startsWith(baseDir)) {
        throw new java.nio.file.AccessDeniedException("Path traversal attempt detected");
    }
    
    fileName = resolvedPath.toString();
    fis = new java.io.FileInputStream(resolvedPath.toFile());
```

## Explanation

The fix addresses two issues: (1) removes the second URL decode that reinterprets traversal sequences, and (2) adds path canonicalization and containment validation. After resolving the candidate path with `toRealPath()`, which follows symlinks and normalizes relative components like `..`, the code verifies the result is inside the base directory using `Path.startsWith(Path)` on the canonical objects. This prevents both `../` traversal and absolute-path injection. The resolved path is then stored in `fileName` to ensure the same canonical value is passed to the file operation, preventing TOCTOU races.

## Behaviour changes

- Removed the second `URLDecoder.decode()` call: cookie values from `request.getCookies()` are already percent-decoded by the servlet container; decoding again corrupts filenames with `+` characters and reinterprets escaped traversal sequences.
- `baseDir.resolve(param)` throws `NoSuchFileException` (a subtype of `IOException`) if the resolved file does not exist; this is the same behavior as the original `new FileInputStream(new File(fileName))`, which also throws `FileNotFoundException` on missing files, so the exception contract is preserved.
- `AccessDeniedException` is thrown for path-traversal attempts (paths outside the base directory) before the file operation; this is a new safety check with no equivalent in the original code, but the finding would have failed at the file operation anyway with `FileNotFoundException` or a permission error.
