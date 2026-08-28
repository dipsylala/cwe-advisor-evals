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
                if (theCookie.getName().equals("BenchmarkTest00002")) {
                    param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
                    break;
                }
            }
        }

        java.io.FileOutputStream fos = null;

        try {
            java.nio.file.Path baseDir =
                    java.nio.file.Paths.get(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR)
                            .toAbsolutePath()
                            .normalize();
            java.nio.file.Files.createDirectories(baseDir);

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

            // The target may not exist yet, so verify containment on the real parent
            // directory: this also defeats a symlinked parent pointing outside the base.
            java.nio.file.Path realBase = baseDir.toRealPath();
            java.nio.file.Path realParent = resolved.getParent().toRealPath();
            if (!realParent.equals(realBase)) {
                rejectRequest(response);
                return;
            }

            // Refuse to follow an existing symlink at the target itself.
            if (java.nio.file.Files.isSymbolicLink(resolved)) {
                rejectRequest(response);
                return;
            }

            String displayName = resolved.getFileName().toString();
            fos = new java.io.FileOutputStream(resolved.toFile(), false);
            response.getWriter()
                    .println(
                            "Now ready to write to file: "
                                    + org.owasp.esapi.ESAPI.encoder().encodeForHTML(displayName));

        } catch (java.nio.file.InvalidPathException | java.io.IOException e) {
            // Log server-side detail only; do not echo the requested path back to the client.
            System.out.println("Couldn't open FileOutputStream on requested file");
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().println("Problem getting FileOutputStream.");
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

    private static void rejectRequest(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.getWriter().println("Invalid file name requested.");
    }
```

## Explanation

The decoded cookie value was concatenated onto `Utils.TESTFILES_DIR` and handed to `new FileOutputStream(fileName, false)`, so a traversal sequence or an absolute path let a caller truncate and overwrite arbitrary files the servlet process could write, which is more damaging than the read case because it can clobber configuration, application code, or startup scripts. The fix constrains the untrusted value to a single bare file name: it is parsed with `Paths.get(...).normalize()` and rejected unless it is relative and has exactly one name component that is neither empty nor `..`, so separators and traversal sequences are structurally impossible rather than filtered. The name is resolved against the normalized absolute base directory and re-checked with `startsWith`. Because a write target legitimately may not exist yet, `toRealPath()` cannot be applied to the file itself, so containment is confirmed on the resolved parent directory instead, and an existing symbolic link at the target is refused outright; together these stop a symlink inside the directory from redirecting the truncating write elsewhere. The write sink therefore always lands on a regular file directly inside the intended directory. The catch block was also tightened to report a generic failure and stop printing the constructed path, so errors do not disclose server filesystem layout.
