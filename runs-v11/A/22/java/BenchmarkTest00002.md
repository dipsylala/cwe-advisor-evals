## Verdict
CONFIRMED

## Source
Line 61: `param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");`

The `param` value originates from a user-supplied cookie and is URL-decoded without validation. At line 71, this untrusted value is concatenated directly to a base directory path to construct a file path, which is then used to open a file at line 74. An attacker can supply path traversal sequences like `../` to access files outside the intended directory.

## Fix
```java
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
    // Construct the intended file path
    java.io.File baseDir = new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR);
    java.io.File targetFile = new java.io.File(baseDir, param);
    
    // Canonicalize both paths and verify the target is within the base directory
    String canonicalBase = baseDir.getCanonicalPath();
    String canonicalTarget = targetFile.getCanonicalPath();
    
    if (!canonicalTarget.startsWith(canonicalBase + java.io.File.separator)) {
        throw new java.io.IOException("Path traversal attempt detected");
    }
    
    fileName = canonicalTarget;
    
    // SAST FINDING: CWE-22 (Path Traversal) - a file path is built from request data and opened. Sink is the next statement.
    fos = new java.io.FileOutputStream(fileName, false);
    response.getWriter()
            .println(
                    "Now ready to write to file: "
                            + org.owasp.esapi.ESAPI.encoder().encodeForHTML(fileName));

} catch (Exception e) {
    System.out.println("Couldn't open FileOutputStream on file: '" + fileName + "'");
    //			System.out.println("File exception caught and swallowed: " + e.getMessage());
} finally {
    if (fos != null) {
        try {
            fos.close();
            fos = null;
        } catch (Exception e) {
            // we tried...
        }
    }
}
```

## Explanation
The vulnerability occurs because untrusted input from a cookie is decoded and directly concatenated with a base directory path without validation. This allows an attacker to use path traversal sequences (`../`) to escape the intended directory and access arbitrary files on the system.

The fix implements canonical path validation:

1. **Construct the target file** using `new java.io.File(baseDir, param)` instead of string concatenation. The File constructor automatically handles path normalization.

2. **Canonicalize both paths** using `getCanonicalPath()`, which resolves all symbolic links and relative path components (`.` and `..`). This produces the absolute path that the operating system will actually access.

3. **Verify containment** by checking that the canonical target path starts with the canonical base directory path followed by a separator. This ensures the resolved file location is within the intended directory and not in a parent or sibling directory.

4. **Reject invalid paths** by throwing an exception if the containment check fails, preventing the file operation from proceeding.

This defense works because:
- Even if `param` contains sequences like `../../etc/passwd`, after canonical resolution the actual path is computed.
- The startsWith check with the separator ensures that a path like `/tmp/override` cannot pass validation for base directory `/tmp/over`.
- Canonical paths are absolute and cannot be bypassed by symbolic links or relative components.
