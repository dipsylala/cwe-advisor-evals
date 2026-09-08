## Verdict

Confirmed. `doPost` builds a filesystem path by concatenating the attacker-controlled `BenchmarkTest00001` cookie value onto `Utils.TESTFILES_DIR` and passes the result straight into `FileInputStream`/`File` with no normalization or containment check. A cookie value such as `../../../../etc/passwd` (URL-decoded before concatenation) lets a caller read any file the servlet process can access, outside the intended `TESTFILES_DIR` sandbox.

## Source

`String param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");` in `doPost`, read from the `BenchmarkTest00001` cookie on the incoming `HttpServletRequest` (line 61). This value flows unmodified into `fileName = Utils.TESTFILES_DIR + param;` (line 71) and then into `new java.io.FileInputStream(new java.io.File(fileName))` (line 73), the reported sink.

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
            // Resolve the requested file against the sandbox directory and canonicalize
            // both paths before use, so ".." segments and symlinks cannot escape
            // TESTFILES_DIR. The canonical containment check is the actual fix; the
            // path is rejected rather than stripped, since stripping "../" can still
            // leave a value that resolves outside the sandbox.
            java.io.File baseDir =
                    new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR)
                            .getCanonicalFile();
            java.io.File requestedFile = new java.io.File(baseDir, param).getCanonicalFile();
            fileName = requestedFile.getPath();

            if (!requestedFile.toPath().startsWith(baseDir.toPath())) {
                throw new SecurityException(
                        "Invalid file path: resolved outside the allowed directory");
            }

            fis = new java.io.FileInputStream(requestedFile);
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

The vulnerable code built `fileName` by string concatenation (`TESTFILES_DIR + param`) with no check that the result stayed inside `TESTFILES_DIR`, so any `../` sequence in the cookie value walked the path out of the sandbox before `FileInputStream` opened it.

The fix replaces the concatenation with `new File(baseDir, param)` and then canonicalizes both the base directory and the resulting file with `getCanonicalFile()`. Canonicalization resolves `.`, `..`, and symlinks into an absolute, normalized form, which is what makes the subsequent `startsWith` check meaningful - a raw string comparison on the uncanonicalized path could be bypassed by traversal sequences or symlinks that a purely lexical check would miss. After canonicalizing, the code verifies `requestedFile.toPath().startsWith(baseDir.toPath())`; if the resolved path is not inside `baseDir`, it throws `SecurityException` and the existing `catch (Exception e)` block reports the problem the same way it already reports a missing file, so the error-handling and response behavior for legitimate requests is unchanged.

This rejects an escaping path outright rather than trying to sanitize or strip `..` from `param`: stripping can still leave a value that resolves outside the sandbox (e.g. via absolute paths or symlinks), whereas resolve-then-verify is robust regardless of how the traversal is encoded. Legitimate requests for files that already live under `TESTFILES_DIR` are unaffected, since their canonical path still starts with the canonical base directory.
