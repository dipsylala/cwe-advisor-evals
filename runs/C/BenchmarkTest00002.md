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
                    // The container already decoded the cookie value; decoding again would
                    // turn an inert literal such as %2e%2e%2f into a real ../ sequence.
                    param = theCookie.getValue();
                    break;
                }
            }
        }

        java.nio.file.Path baseDir;
        java.nio.file.Path target;
        try {
            baseDir =
                    java.nio.file.Paths.get(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR)
                            .toRealPath();

            // Secondary control: refuse traversal sequences, absolute paths and null bytes
            // outright rather than stripping them, so the attempt is visible and not repaired.
            if (param.isEmpty()
                    || param.indexOf(0) >= 0
                    || param.contains("..")
                    || param.startsWith("/")
                    || param.startsWith("\\")
                    || param.contains("/")
                    || param.contains("\\")) {
                throw new java.nio.file.InvalidPathException(param, "Rejected file name");
            }

            // Primary control: resolve against the base directory and require containment,
            // compared component-wise on Path objects. The target may not exist yet, so the
            // symlink-resolving canonicalization is applied to its parent directory.
            target = baseDir.resolve(param).normalize();
            java.nio.file.Path parent = target.getParent();
            if (target.equals(baseDir)
                    || !target.startsWith(baseDir)
                    || parent == null
                    || !parent.toRealPath().equals(baseDir)) {
                throw new java.nio.file.InvalidPathException(param, "Outside base directory");
            }
        } catch (java.nio.file.InvalidPathException | IOException e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().println("Invalid file requested");
            return;
        }

        String fileName = target.toString();

        // The validated Path object itself is what gets opened - the name is not re-derived.
        // NOFOLLOW_LINKS stops an existing symlink at the target from redirecting the write.
        try (java.io.OutputStream fos =
                java.nio.file.Files.newOutputStream(
                        target,
                        java.nio.file.StandardOpenOption.CREATE,
                        java.nio.file.StandardOpenOption.WRITE,
                        java.nio.file.StandardOpenOption.TRUNCATE_EXISTING,
                        java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            response.getWriter()
                    .println(
                            "Now ready to write to file: "
                                    + org.owasp.esapi.ESAPI.encoder().encodeForHTML(fileName));
        } catch (Exception e) {
            System.out.println("Couldn't open OutputStream on file: '" + fileName + "'");
        }
    }
```

## Explanation

The cookie value was concatenated onto `TESTFILES_DIR` and handed straight to `new FileOutputStream(...)`, so input such as `../../webapps/ROOT/shell.jsp` let an attacker choose where the write landed, and the extra `URLDecoder.decode()` call manufactured that traversal from encoded literals like `%2e%2e%2f` that the container had already decoded once. The fix removes the second decode and replaces concatenation with resolve-and-contain: the base directory is canonicalized with `toRealPath()`, the supplied name is rejected outright if it is empty, absolute, contains a null byte, a separator or `..`, and the resolved candidate must sit inside the base according to `Path.startsWith(Path)` — a component-aware check, so a sibling such as `testfiles-backup` cannot pass the way a plain string prefix test would allow. Because a write target need not already exist, `toRealPath()` is applied to the parent directory instead, which resolves any symlinked directory before the containment decision, and `NOFOLLOW_LINKS` on the open prevents a pre-planted symlink at the target name from redirecting the write outside the root. The validated `Path` is the exact object passed to `Files.newOutputStream`, so nothing re-derives the path between the check and the open, and rejected input yields a 400 with a generic message.
