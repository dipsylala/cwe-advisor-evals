## Verdict
exploitable

## Source
Line 61: Cookie value extracted via `theCookie.getValue()`, URL-decoded into `param`

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
            fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;
            
            // Validate that the resolved path stays within the base directory
            String baseDir = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR;
            String canonicalBasePath = new java.io.File(baseDir).getCanonicalPath();
            if (!canonicalBasePath.endsWith(java.io.File.separator)) {
                canonicalBasePath += java.io.File.separator;
            }
            
            String canonicalFilePath = new java.io.File(fileName).getCanonicalPath();
            
            if (!canonicalFilePath.startsWith(canonicalBasePath)) {
                throw new IOException("Attempted path traversal outside base directory");
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
The vulnerability stems from constructing a file path by concatenating a base directory with unsanitized cookie input. An attacker can inject path-traversal sequences like `../../../etc/passwd` to escape the intended directory. The fix implements the canonical-path containment pattern recommended by CWE-22 guidance: (1) obtain the canonical (absolute, symlink-resolved) form of both the base directory and the requested file path using `getCanonicalPath()`, (2) append a path separator to the base directory to avoid matching sibling directories (e.g., `/app/uploads` matching `/app/uploads-backup`), and (3) verify that the canonical file path starts with the separator-terminated canonical base path before proceeding to open the file. If the containment check fails, an IOException is thrown immediately. This approach defeats both direct path traversal (`../`) and symlink-based attacks since `getCanonicalPath()` resolves symlinks to their actual targets.

## Behaviour changes
- Added path canonicalization logic (lines 73-81): calls to `getCanonicalPath()` on File objects are new, as is the string concatenation of the separator. These are purely defensive and do not alter behavior on legitimate requests within the intended directory.
- Added containment check (line 83): throws IOException if canonical paths do not align. This is a security gate; legitimate file access is unaffected, but requests attempting traversal now fail safely with a clear error message instead of succeeding.
- Exception message improved: the new IOException message "Attempted path traversal outside base directory" is more informative than the generic exception handling that follows, aiding in security audit logging.
- No change to return value, file handle behavior, or normal-case control flow: on successful containment validation, the file is opened and processed exactly as before.
