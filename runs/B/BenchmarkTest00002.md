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
                    // No second decode: the cookie value is used exactly as received.
                    param = theCookie.getValue();
                    break;
                }
            }
        }

        java.io.OutputStream fos = null;

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

            // The destination may not exist yet, so canonicalize the parent - which does -
            // and require it to be the base directory itself.
            java.nio.file.Path target = baseDir.resolve(param);
            java.nio.file.Path parent = target.getParent().toRealPath();
            if (!parent.equals(baseDir)) {
                throw new java.nio.file.AccessDeniedException(param);
            }

            // An existing symlink at the destination would redirect the write outside the base.
            if (java.nio.file.Files.isSymbolicLink(target)) {
                throw new java.nio.file.AccessDeniedException(param);
            }

            // Write to the exact path that was validated.
            fos =
                    java.nio.file.Files.newOutputStream(
                            target,
                            java.nio.file.StandardOpenOption.CREATE,
                            java.nio.file.StandardOpenOption.WRITE,
                            java.nio.file.StandardOpenOption.TRUNCATE_EXISTING);
            response.getWriter()
                    .println(
                            "Now ready to write to file: "
                                    + org.owasp.esapi.ESAPI.encoder()
                                            .encodeForHTML(target.getFileName().toString()));

        } catch (Exception e) {
            System.out.println("Couldn't open output stream for requested file: '" + param + "'");
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

The cookie value was concatenated onto the test-files directory and passed directly to `new FileOutputStream(fileName, false)`, letting an attacker steer a truncating write to any path the process can reach via `../` or an absolute path. Because this is a write, the destination need not exist and `toRealPath()` on the candidate itself would simply fail, so the check is anchored on the parent instead: the base directory is canonicalized with `toRealPath()`, the untrusted value is required to be a single path component (rejecting empty values, embedded null bytes, and anything where `Paths.get(param).getFileName().toString()` differs from `param`), and the resolved target's canonicalized parent must equal that base - a `Path` comparison rather than a string prefix test, so a sibling directory cannot slip through. An existing symbolic link at the destination is rejected, since following one would redirect the write outside the base even after the parent check passes, and the stream is opened from the same validated `target` variable so no separate unchecked path reaches the sink. The redundant `URLDecoder.decode()` pass was removed because it turns an already-inert `%2e%2e%2f` literal into a real traversal sequence and corrupts `+` in legitimate names, and the response now echoes only the file name rather than the full server path.
