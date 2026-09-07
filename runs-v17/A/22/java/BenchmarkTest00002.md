## Verdict
VULNERABLE - Path traversal via URL-decoded cookie value used directly in file path construction without validation.

## Source
Cookie `BenchmarkTest00002` is extracted at line 55-64, URL-decoded at line 61, and used at line 71 to construct a file path without validating that it remains within the intended directory.

## Fix
### File: BenchmarkTest00002.java
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

@WebServlet(value = "/pathtraver-00/BenchmarkTest00002")
public class BenchmarkTest00002 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        javax.servlet.http.Cookie userCookie =
                new javax.servlet.http.Cookie("BenchmarkTest00002", "FileName");
        userCookie.setMaxAge(60 * 3); // Store cookie for 3 minutes
        userCookie.setSecure(true);
        userCookie.setHttpOnly(true);
        userCookie.setPath(request.getRequestURI());
        userCookie.setDomain(new java.net.URL(request.getRequestURL().toString()).getHost());
        response.addCookie(userCookie);
        javax.servlet.RequestDispatcher rd =
                request.getRequestDispatcher("/pathtraver-00/BenchmarkTest00002.html");
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
                if (theCookie.getName().equals("BenchmarkTest00002")) {
                    param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
                    break;
                }
            }
        }

        String fileName = null;
        java.io.FileOutputStream fos = null;

        try {
            String baseDir = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR;
            java.nio.file.Path basePath = java.nio.file.Paths.get(baseDir).toAbsolutePath().normalize();
            java.nio.file.Path targetPath = basePath.resolve(param).normalize();

            if (!targetPath.startsWith(basePath)) {
                throw new IllegalArgumentException("Path traversal detected: target path escapes base directory");
            }

            fileName = targetPath.toString();

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
    }
}
```

## Explanation
The fix uses `java.nio.file.Path` API to safely resolve and validate the file path:

1. **Resolve the base directory**: Convert `TESTFILES_DIR` to an absolute, normalized path using `toAbsolutePath().normalize()`, which resolves all `.` and `..` references.

2. **Resolve the target path**: Use `basePath.resolve(param)` to safely combine the base directory with the user-supplied filename, then normalize it.

3. **Validate containment**: Verify that the target path `startsWith(basePath)`. This ensures the file operation stays within the intended directory, preventing path traversal via `../` sequences or absolute paths.

4. **Reject traversal attempts**: If the target path would escape the base directory, throw an `IllegalArgumentException` which is caught by the existing exception handler.

This defense prevents an attacker from using sequences like `../../etc/passwd` or absolute paths to access files outside the designated directory.
