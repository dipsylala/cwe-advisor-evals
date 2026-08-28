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
                if (theCookie.getName().equals("BenchmarkTest00001")) {
                    // No second decode: the cookie value is used exactly as received.
                    param = theCookie.getValue();
                    break;
                }
            }
        }

        java.io.InputStream fis = null;

        try {
            java.nio.file.Path baseDir =
                    java.nio.file.Paths.get(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR)
                            .toRealPath();

            // The cookie may supply a bare file name only - never a path or a traversal sequence.
            if (param.isEmpty()
                    || param.indexOf('\u0000') >= 0
                    || !param.equals(java.nio.file.Paths.get(param).getFileName().toString())) {
                throw new java.nio.file.InvalidPathException(param, "Not a simple file name");
            }

            // Canonicalize (follows symbolic links), then confirm containment by path component.
            java.nio.file.Path resolved = baseDir.resolve(param).toRealPath();
            if (!resolved.startsWith(baseDir)) {
                throw new java.nio.file.AccessDeniedException(param);
            }

            // Open the exact path that was validated.
            fis = java.nio.file.Files.newInputStream(resolved);
            byte[] b = new byte[1000];
            int size = fis.read(b);
            if (size < 0) {
                size = 0;
            }
            response.getWriter()
                    .println(
                            "The beginning of file: '"
                                    + org.owasp.esapi.ESAPI.encoder()
                                            .encodeForHTML(resolved.getFileName().toString())
                                    + "' is:\n\n"
                                    + org.owasp
                                            .esapi
                                            .ESAPI
                                            .encoder()
                                            .encodeForHTML(new String(b, 0, size)));
        } catch (Exception e) {
            System.out.println("Couldn't open requested file: '" + param + "'");
            response.getWriter().println("Problem getting FileInputStream");
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
    }
```

## Explanation

The cookie value previously flowed straight into a concatenated path string that was handed to `new FileInputStream(new File(...))`, so any `../` sequence (or an absolute path) escaped the test-files directory. The replacement resolves the base directory to its canonical form with `toRealPath()`, requires the untrusted value to be a single path component by rejecting anything where `Paths.get(param).getFileName().toString()` differs from `param` (also rejecting empty values and embedded null bytes), then resolves the candidate against that base and canonicalizes it with `toRealPath()` so symbolic links and relative segments are collapsed before validation. Containment is enforced by comparing `java.nio.file.Path` objects with `resolved.startsWith(baseDir)` rather than string prefixes, which prevents a sibling directory such as a `-backup` suffix from passing, and the stream is opened from that same validated `resolved` variable so no second, unchecked path is derived for the open. The redundant `URLDecoder.decode()` pass was dropped because it re-decodes an already-inert literal such as `%2e%2e%2f` into `../` and mangles `+` in legitimate names; the error path no longer echoes the constructed path or exception text back to the client.
