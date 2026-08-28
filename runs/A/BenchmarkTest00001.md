## Fix

```java
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");

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

        java.io.FileInputStream fis = null;
        String displayName = "";

        try {
            java.nio.file.Path baseDir =
                    java.nio.file.Paths.get(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR)
                            .toAbsolutePath()
                            .normalize();

            // Treat the request value as a bare file name only: reject absolute paths,
            // any path separator, and any parent-directory reference.
            java.nio.file.Path candidate = java.nio.file.Paths.get(param).normalize();
            if (candidate.isAbsolute()
                    || candidate.getNameCount() != 1
                    || candidate.getName(0).toString().isEmpty()
                    || candidate.getName(0).toString().equals("..")) {
                rejectRequest(response);
                return;
            }

            java.nio.file.Path resolved = baseDir.resolve(candidate).normalize();
            if (!resolved.startsWith(baseDir)) {
                rejectRequest(response);
                return;
            }

            // Resolve symlinks before opening so a link inside the directory
            // cannot redirect the read outside it.
            java.nio.file.Path realBase = baseDir.toRealPath();
            java.nio.file.Path realTarget = resolved.toRealPath();
            if (!realTarget.startsWith(realBase)
                    || !java.nio.file.Files.isRegularFile(realTarget)) {
                rejectRequest(response);
                return;
            }

            displayName = realTarget.getFileName().toString();
            fis = new java.io.FileInputStream(realTarget.toFile());
            byte[] b = new byte[1000];
            int size = fis.read(b);
            response.getWriter()
                    .println(
                            "The beginning of file: '"
                                    + org.owasp.esapi.ESAPI.encoder().encodeForHTML(displayName)
                                    + "' is:\n\n"
                                    + org.owasp
                                            .esapi
                                            .ESAPI
                                            .encoder()
                                            .encodeForHTML(new String(b, 0, size)));
        } catch (java.nio.file.InvalidPathException | java.io.IOException e) {
            // Log server-side detail only; do not echo the requested path back to the client.
            System.out.println("Couldn't open FileInputStream on requested file");
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().println("Problem getting FileInputStream.");
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

    private static void rejectRequest(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.getWriter().println("Invalid file name requested.");
    }
```

## Explanation

The cookie value flowed straight into string concatenation with `Utils.TESTFILES_DIR` and then into `new FileInputStream(...)`, so a value such as `../../etc/passwd` (or an absolute path, which would discard the prefix entirely) let the caller read any file the servlet process could open. The fix stops trusting the value as a path fragment and instead constrains it to a single bare file name: the decoded value is parsed with `Paths.get(...).normalize()` and rejected unless it is relative and consists of exactly one name component that is neither empty nor `..`, which eliminates separators and traversal sequences rather than trying to filter them out. The name is then resolved against the normalized, absolute base directory and re-checked with `startsWith`, and `toRealPath()` is applied to both base and target so symlinks are followed before the containment decision is made, closing the link-escape and TOCTOU-style gaps that a purely lexical check leaves open; `isRegularFile` also rejects directories and device files. Because the opened path is now provably inside the intended directory, the sink is no longer attacker-controlled. The error path was also changed to report a generic message and echo only the resolved file name, so failures no longer disclose server paths or filesystem structure.
