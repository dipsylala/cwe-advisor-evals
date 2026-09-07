## Verdict
Path Traversal (CWE-22) confirmed. User-supplied cookie value is used in a file path without validation, allowing directory traversal attacks.

## Source
Lines 55-73: Cookie value is extracted and URL-decoded without validation, then concatenated into a file path and used to open a file.

```
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
fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;
fis = new java.io.FileInputStream(new java.io.File(fileName));
```

An attacker controlling the cookie can provide `../../../etc/passwd` or similar payloads to read files outside the intended directory.

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
            // Validate that the requested file is within the base directory
            java.io.File baseDir = new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR);
            java.io.File requestedFile = new java.io.File(baseDir, param);
            
            // Resolve canonical paths to prevent directory traversal
            String basePath = baseDir.getCanonicalPath();
            String requestedPath = requestedFile.getCanonicalPath();
            
            // Ensure the requested file is within the base directory
            if (!requestedPath.startsWith(basePath + java.io.File.separator) && !requestedPath.equals(basePath)) {
                throw new java.io.IOException("Path traversal attempt detected");
            }
            
            fileName = requestedPath;
            // SAST FINDING: CWE-22 (Path Traversal) - a file path is built from request data and opened. Sink is the next statement.
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
The fix prevents path traversal by validating that any user-supplied filename stays within the intended base directory:

1. **Construct the file path safely**: Use `File(baseDir, param)` constructor which treats `param` as a relative path component within `baseDir`, rather than simple string concatenation.

2. **Resolve canonical paths**: Call `getCanonicalPath()` on both the base directory and the requested file to resolve all symlinks and relative path components (like `..` and `.`).

3. **Validate the path**: Ensure the canonical path of the requested file either starts with the base directory's path (with a separator) or equals it exactly. This prevents the attacker from escaping the intended directory using traversal sequences.

4. **Fail securely**: If validation fails, throw an `IOException` which is caught and handled appropriately, denying access rather than reading arbitrary files.

This approach implements the principle of least privilege for file access: only files within the designated safe directory are readable, and any attempt to access files outside it is rejected.
