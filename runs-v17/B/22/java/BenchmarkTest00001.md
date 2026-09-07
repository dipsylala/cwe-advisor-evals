## Verdict
VULNERABLE: Path traversal via unsanitized cookie value concatenated with directory path and opened without containment validation.

## Source
Cookie value from HTTP request, URL-decoded at line 61, assigned to `param` variable.

## Fix

### File: BenchmarkTest00001.java

```java
/**
 * OWASP Benchmark v1.2
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project. For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author Dave Wichers
 * @created 2015
 */
package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/pathtraver-00/BenchmarkTest00001")
public class BenchmarkTest00001 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        javax.servlet.http.Cookie userCookie =
                new javax.servlet.http.Cookie("BenchmarkTest00001", "FileName");
        userCookie.setMaxAge(60 * 3); // Store cookie for 3 minutes
        userCookie.setSecure(true);
        userCookie.setHttpOnly(true);
        userCookie.setPath(request.getRequestURI());
        userCookie.setDomain(new java.net.URL(request.getRequestURL().toString()).getHost());
        response.addCookie(userCookie);
        javax.servlet.RequestDispatcher rd =
                request.getRequestDispatcher("/pathtraver-00/BenchmarkTest00001.html");
        rd.include(request, response);
    }

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
                    param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
                    break;
                }
            }
        }

        String fileName = null;
        java.io.FileInputStream fis = null;

        try {
            // Reject paths containing traversal sequences or absolute paths
            if (param.contains("..") || new java.io.File(param).isAbsolute()) {
                throw new IllegalArgumentException("Invalid file name: traversal or absolute path detected");
            }

            fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;

            // Canonicalize paths and verify containment within base directory
            java.nio.file.Path basePath = java.nio.file.Paths.get(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR).toRealPath();
            java.nio.file.Path requestedPath = new java.io.File(fileName).getCanonicalFile().toPath();

            if (!requestedPath.startsWith(basePath)) {
                throw new IllegalArgumentException("Path traversal attempt detected");
            }

            fis = new java.io.FileInputStream(new java.io.File(fileName));
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
    }
}
```

## Explanation

The vulnerability exists because the cookie value (`param`) is concatenated directly with a base directory path and then opened without validating that the resulting path stays within the intended directory. An attacker can set the cookie to `../../../etc/passwd` to escape the directory boundary.

The fix adds three layers of defense as prescribed by CWE-22 Java guidance:

1. **Traversal sequence rejection:** Reject any `param` containing `..` or representing an absolute path before path construction.
2. **Path canonicalization:** Resolve both the base directory and the constructed file path to their canonical (absolute, symlink-resolved) forms using `toRealPath()` and `getCanonicalFile()`.
3. **Containment verification:** Use `Path.startsWith(Path)` to verify the canonicalized requested path is within the canonicalized base directory. This prevents sibling directory escape (e.g., `/app/uploads-backup` passing a string-prefix check on `/app/uploads`).

The fix preserves the existing contract: files are still opened for reading via `FileInputStream`, exceptions are caught and reported, and the original error-handling flow remains intact.

## Behaviour changes

- Requests with cookie values containing `..` or absolute paths now throw `IllegalArgumentException` instead of attempting file access.
- Requests with cookie values that resolve to files outside the base directory now throw `IllegalArgumentException` instead of attempting file access.
- All legitimate file accesses within the base directory proceed as before.
- Exception messages reflect the new validation failures in the catch block's generic handler.
