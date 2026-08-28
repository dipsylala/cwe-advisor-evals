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
                    || param.indexOf('\0') >= 0
                    || param.contains("..")
                    || param.startsWith("/")
                    || param.startsWith("\\")
                    || param.contains("/")
                    || param.contains("\\")) {
                throw new java.nio.file.InvalidPathException(param, "Rejected file name");
            }

            // Primary control: canonicalize (resolving symlinks) and require containment
            // in the base directory, compared component-wise on Path objects.
            target = baseDir.resolve(param).normalize().toRealPath();
            if (!target.startsWith(baseDir) || target.equals(baseDir)) {
                throw new java.nio.file.InvalidPathException(param, "Outside base directory");
            }
        } catch (java.nio.file.InvalidPathException | IOException e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().println("Invalid file requested");
            return;
        }

        String fileName = target.toString();

        // The validated Path object itself is what gets opened - the name is not re-derived.
        try (java.io.InputStream fis = java.nio.file.Files.newInputStream(target)) {
            byte[] b = new byte[1000];
            int size = fis.read(b);
            if (size < 0) {
                size = 0;
            }
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
            System.out.println("Couldn't open InputStream on file: '" + fileName + "'");
            response.getWriter().println("Problem getting InputStream for the requested file");
        }
    }
```

## Explanation

The cookie value flowed straight into a concatenated path and then into `new FileInputStream(...)`, so a value such as `../../etc/passwd` escaped the intended `TESTFILES_DIR` root, and the extra `URLDecoder.decode()` call made things worse by converting encoded literals like `%2e%2e%2f` into real separators after the container had already decoded once. The fix drops that second decode and replaces string concatenation with a resolve-and-contain check: the base directory is canonicalized with `toRealPath()`, the user-supplied name is rejected outright if it is empty, absolute, contains a null byte, a path separator or `..`, and the candidate is then canonicalized (which resolves `.`, `..` and symbolic links) and required to sit strictly inside the base via `Path.startsWith(Path)` — a component-aware comparison, so a sibling directory like `testfiles-backup` cannot slip through the way a raw string prefix test would allow. The exact `Path` object that passed validation is the one handed to `Files.newInputStream`, so there is no second, unchecked derivation of the path between the check and the open, and any rejected or unresolvable input produces a 400 with a generic message rather than echoing filesystem details back to the caller.
