## Verdict

Path Traversal is **exploitable**. The vulnerability allows attackers to access arbitrary files on the system outside the intended directory.

## Source

The attacker-controlled source is the HTTP cookie value at line 55-65:

```java
javax.servlet.http.Cookie[] theCookies = request.getCookies();

String param = "noCookieValueSupplied";
if (theCookies != null) {
    for (javax.servlet.http.Cookie theCookie : theCookies) {
        if (theCookie.getName().equals("BenchmarkTest00001")) {
            param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
            break;
        }
    }
}
```

The cookie value flows directly into file path construction at line 71 without any validation or canonicalization.

## Fix

**Remove the extra URLDecoder.decode() and add path canonicalization with containment validation:**

```java
javax.servlet.http.Cookie[] theCookies = request.getCookies();

String param = "noCookieValueSupplied";
if (theCookies != null) {
    for (javax.servlet.http.Cookie theCookie : theCookies) {
        if (theCookie.getName().equals("BenchmarkTest00001")) {
            // Container already decoded; do not decode again
            param = theCookie.getValue();
            break;
        }
    }
}

String fileName = null;
java.io.FileInputStream fis = null;

try {
    // Canonicalize the base directory
    java.nio.file.Path basePath = new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR).toPath().toRealPath();
    
    // Resolve and canonicalize the candidate path
    java.nio.file.Path candidatePath = basePath.resolve(param).toRealPath();
    
    // Verify the resolved path stays within the base directory
    if (!candidatePath.startsWith(basePath)) {
        throw new SecurityException("Path traversal attempt detected");
    }
    
    fileName = candidatePath.toString();
    fis = new java.io.FileInputStream(candidatePath.toFile());
    byte[] b = new byte[1000];
    int size = fis.read(b);
    response.getWriter()
            .println(
                    "The beginning of file: '"
                            + org.owasp.esapi.ESAPI.encoder().encodeForHTML(fileName)
                            + "' is:\n\n"
                            + org.owasp
                                    .esapi
                                    .ESAPI
                                    .encoder()
                                    .encodeForHTML(new String(b, 0, size)));
} catch (Exception e) {
    System.out.println("Couldn't open FileInputStream on file: '" + fileName + "'");
    response.getWriter()
            .println(
                    "Problem getting FileInputStream: "
                            + org.owasp
                                    .esapi
                                    .ESAPI
                                    .encoder()
                                    .encodeForHTML(e.getMessage()));
} finally {
    if (fis != null) {
        try {
            fis.close();
            fis = null;
        } catch (Exception e) {
            // we tried...
        }
    }
}
```

## Explanation

The vulnerability had two compounding problems:

1. **Extra URLDecoder.decode()**: The servlet container already percent-decodes cookie values when it parses the HTTP request. Calling `URLDecoder.decode()` a second time turns inert literals like `%2e%2e%2f` (URL-encoded `../`) back into path-traversal sequences. This was the entry point for the exploit.

2. **No path validation**: The param value was concatenated directly to the base directory path without any check that the result stayed within that directory. An attacker could send `../../../etc/passwd` in the cookie to escape the intended directory.

The fix implements the three-step defence prescribed by CWE-22:

- **Canonicalization**: `Path.toRealPath()` resolves symbolic links and relative references (`.`, `..`) into absolute paths, eliminating any tricks that might disguise a traversal attempt.
- **Containment check**: `Path.startsWith(basePath)` verifies component-by-component that the canonical target path is inside or equal to the base directory. String comparison would fail on sibling directories like `/app/uploads-secret` passing a `startsWith("/app/uploads")` test.
- **Use the validated path**: The canonical path is captured into a variable and that same variable is used for the file operation, preventing the code from validating one path and then opening a different one.

## Behaviour changes

- Requests with paths containing `../`, absolute paths, or symlink escapes now raise a `SecurityException` instead of silently granting access to files outside the intended directory.
- A path like `targetfile.txt` that exists in `TESTFILES_DIR` will continue to open successfully. A path like `../sensitive.xml` will now be rejected.
- Double-encoded sequences like `%252e%252e%252f` (which would decode to `%2e%2e%2f`, then to `../`) are no longer decoded a second time, preventing a covert traversal attempt disguised as a literal filename.
- The error message is more precise: a traversal attempt now reports `SecurityException: Path traversal detected` in the logs, aiding auditing.
