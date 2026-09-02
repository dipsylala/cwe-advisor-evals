## Verdict

Confirmed. `doPost` builds a filesystem path by concatenating a fixed base directory with an attacker-controlled value and opens it for writing without validating that the result stays inside the base directory.

## Source

The tainted value originates from an HTTP cookie named `BenchmarkTest00002`, read from `request.getCookies()` in `doPost` (line 55-64) and URL-decoded into `param` (line 61). `param` defaults to a safe literal only when the cookie is absent; when the cookie is present, its value is attacker-controlled and reaches the sink unchanged. A cookie value such as `..%2F..%2F..%2Fetc%2Fpasswd` (or a Windows equivalent) decodes to `../../../etc/passwd` and, once concatenated onto `TESTFILES_DIR`, resolves outside the intended directory.

## Fix

```java
@Override
public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    // some code
    response.setContentType("text/html;charset=UTF-8");

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
        java.nio.file.Path baseDir =
                java.nio.file.Paths.get(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR)
                        .toAbsolutePath()
                        .normalize();

        // Reject path separators / traversal sequences outright: this sink only ever
        // needs a bare file name inside baseDir, never a nested path.
        if (param.contains("/") || param.contains("\\") || param.contains("..")) {
            throw new SecurityException("Invalid file name: " + param);
        }

        java.nio.file.Path resolved = baseDir.resolve(param).normalize();

        // Defense in depth: confirm the resolved path still lives under baseDir even
        // if a future change loosens the character check above.
        if (!resolved.startsWith(baseDir)) {
            throw new SecurityException("Path traversal attempt blocked: " + param);
        }

        fileName = resolved.toString();

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
}
```

## Explanation

The original code trusts the decoded cookie value as a bare file name and hands it straight to `FileOutputStream`, so any `../` sequence (or an absolute path on some platforms) lets the request write outside `TESTFILES_DIR`. The fix applies two layers: it first rejects any value containing a path separator or `..` segment, since the legitimate use case is a single file name with no directory component; then, as defense in depth, it resolves the candidate against the canonical, normalized base directory and confirms with `Path.startsWith` that the result has not escaped it before the path is ever used to open a file. Both checks run before `fileName` is assigned, so a rejected value never reaches the `FileOutputStream` sink, and the existing catch/finally structure, ESAPI HTML encoding of the echoed path, and cookie-handling logic are left untouched.
