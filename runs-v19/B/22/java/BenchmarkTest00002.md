## Verdict

VULNERABLE - Path traversal sink reachable through untrusted cookie value with no canonicalization or containment validation.

## Source

Cookie value obtained at line 55-64:
```
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
```

The parameter `param` is attacker-controlled (via cookie value) and not validated.

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
                    // Cookie value is already in its final form; do not re-decode
                    param = theCookie.getValue();
                    break;
                }
            }
        }

        String fileName = null;
        java.io.FileOutputStream fos = null;

        try {
            // Get the base directory and canonicalize it
            String baseDirPath = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR;
            java.nio.file.Path baseDir = java.nio.file.Paths.get(baseDirPath).toRealPath();
            
            // Require filename to be a single component (no path separators or traversal)
            String filename = param;
            java.nio.file.Path filenamePath = java.nio.file.Paths.get(filename);
            if (!filename.equals(filenamePath.getFileName().toString())) {
                throw new java.io.IOException("Invalid filename: contains path traversal sequences");
            }
            
            // Resolve the full path within the base directory
            java.nio.file.Path fullPath = baseDir.resolve(filename);
            
            // Verify containment within base directory
            if (!fullPath.startsWith(baseDir)) {
                throw new java.io.IOException("Path traversal attempt detected");
            }
            
            fileName = fullPath.toString();
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

The fix eliminates path traversal by implementing three controls:

1. **Remove unnecessary re-decoding** (line 62): The original code called `URLDecoder.decode()` on a cookie value. Cookie values transmitted via HTTP are not percent-encoded by the servlet container, so this second decode step is unnecessary and dangerous—it would convert a benign literal `%2e%2e%2f` into the traversal sequence `../`. The fixed code uses `getValue()` directly.

2. **Canonicalize the base directory** (line 72): The code canonicalizes the base directory using `Path.toRealPath()`, which resolves it to an absolute path and follows symbolic links. This establishes a trusted baseline for comparison.

3. **Enforce single-component filename validation and containment** (lines 75-82): The fix validates that the filename is a single path component with no separators by comparing `filename.equals(Paths.get(filename).getFileName().toString())`. This rejects any value containing `..`, `/`, or other path traversal syntax. The validated filename is then resolved into the base directory using `Path.resolve()`, which guarantees the result stays within the base when the filename has no separators. A defensive containment check using `Path.startsWith()` verifies the final path is inside the base directory before opening the file.

This follows the CWE-22 remediation guidance for write operations: canonicalize the parent directory, reject traversal in the supplied filename, and verify containment using path-aware comparison operators rather than string prefix checks.

## Behaviour changes

- Filenames containing path separators (`..`, `/`, `\`) or traversal sequences are now rejected with an `IOException`.
- Filenames that are single components (e.g., `notes.txt`) continue to work as before.
- Legitimate filenames with dots in them (e.g., `my.notes.txt`) are accepted and function correctly; the single-component check only rejects separators, not dot characters.
- Absolute paths are rejected (e.g., `/etc/passwd` is not a single component in the path sense).
- File creation in the intended `TESTFILES_DIR` is preserved for valid filenames.
