## Verdict

Path Traversal vulnerability confirmed. User-controlled cookie input is used to construct a file path and passed directly to FileOutputStream without validation, allowing an attacker to use sequences like `../` to escape the intended directory and access or write arbitrary files.

## Source

- **Entry point**: Cookie with name "BenchmarkTest00002" (line 59-64)
- **Data flow**: 
  - Cookie value extracted at line 61: `param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8")`
  - Path constructed at line 71: `fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param`
  - **Sink** at line 74: `fos = new java.io.FileOutputStream(fileName, false)`

Attacker control: Complete. An attacker can set the "BenchmarkTest00002" cookie to any value, including traversal sequences like `../../../../etc/passwd`, to read/write files outside the intended directory.

## Fix

**Before (lines 59-78):**
```java
javax.servlet.http.Cookie[] theCookies = request.getCookies();

String param = "noCookieValueSupplied";
if (theCookies != null) {
    for (javax.servlet.http.Cookie theCookie : theCookies) {
        if (theCookie.getName().equals("BenchmarkTest00002")) {
            param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
            break;
        }
    }
}

String fileName = null;
java.io.FileOutputStream fos = null;

try {
    fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;

    // SAST FINDING: CWE-22 (Path Traversal) - a file path is built from request data and opened. Sink is the next statement.
    fos = new java.io.FileOutputStream(fileName, false);
    response.getWriter()
            .println(
                    "Now ready to write to file: "
                            + org.owasp.esapi.ESAPI.encoder().encodeForHTML(fileName));
```

**After (corrected code):**
```java
javax.servlet.http.Cookie[] theCookies = request.getCookies();

String param = "noCookieValueSupplied";
if (theCookies != null) {
    for (javax.servlet.http.Cookie theCookie : theCookies) {
        if (theCookie.getName().equals("BenchmarkTest00002")) {
            param = theCookie.getValue(); // Do not re-decode; use raw cookie value
            break;
        }
    }
}

String fileName = null;
java.io.FileOutputStream fos = null;

try {
    // Canonicalize the base directory
    java.nio.file.Path baseDir = java.nio.file.Paths.get(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR).toRealPath();
    
    // Validate param is a single filename component (no path separators or traversal)
    if (!java.nio.file.Paths.get(param).getFileName().toString().equals(param)) {
        throw new IOException("Invalid filename: path traversal blocked");
    }
    
    // Construct and verify the file path
    java.nio.file.Path filePath = baseDir.resolve(param);
    if (!filePath.toAbsolutePath().startsWith(baseDir)) {
        throw new IOException("Path traversal detected");
    }
    
    fileName = filePath.toString();
    fos = new java.io.FileOutputStream(fileName, false);
    response.getWriter()
            .println(
                    "Now ready to write to file: "
                            + org.owasp.esapi.ESAPI.encoder().encodeForHTML(fileName));
```

## Explanation

The fix implements two layers of defense, per the CWE-22 Java guidance:

1. **Removed unnecessary URL decoding** (line 61): `Cookie.getValue()` returns the raw cookie value. The original `URLDecoder.decode()` is not needed for cookies and creates a double-decoding risk if the value is already encoded. Removing it simplifies the input validation.

2. **Canonicalized and validated the path** (lines 71-79):
   - `baseDir.toRealPath()` resolves the base directory to absolute canonical form, following symlinks
   - The filename component check `Paths.get(param).getFileName().toString().equals(param)` ensures `param` is a single filename with no directory separators, relative path references (`..`, `.`), or absolute paths. Any traversal attempt fails this check.
   - `baseDir.resolve(param)` safely combines the paths
   - The final `startsWith(baseDir)` verification confirms the result stays within the intended directory (defense in depth)
   - If validation fails, an IOException is thrown and caught by the existing exception handler

The fix preserves the sink's contract: `FileOutputStream` is still constructed with the resolved absolute path string, error handling remains unchanged, and the output message still displays the sanitized filename.

## Behaviour changes

- **Invalid input rejection**: Filenames containing directory separators, traversal sequences (`..`), or absolute path indicators (leading `/` or `\`) are now rejected with an IOException, which is caught and logged as before ("Couldn't open FileOutputStream on file...")
- **Path expansion**: The resolved filename is now expanded to an absolute canonical path (e.g., `C:\app\files\myfile.txt` instead of a relative or symlink-containing path), ensuring the file operation targets the correct location
- **Security hardening**: An attacker cannot use sequences like `../../../etc/passwd`, `..%5c..%5c`, or symlinks to escape the intended directory
- **Output format**: The output message now displays the canonical absolute path instead of the relative or base-concatenated form
