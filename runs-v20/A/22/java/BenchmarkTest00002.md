## Verdict

Confirmed. `doPost` builds a filesystem path by concatenating a fixed base directory with `param`, a value taken verbatim from a request cookie, and then opens that path with `FileOutputStream`. Because the cookie value is never validated, an attacker can supply a value such as `../../../../etc/passwd` (or a Windows equivalent) to make the server create or truncate an arbitrary file outside the intended `TESTFILES_DIR` directory.

## Source

`request.getCookies()` → the cookie named `BenchmarkTest00002` → `theCookie.getValue()`, URL-decoded into `param` (line 61). `param` is fully attacker-controlled: cookies are set by the client and are not authenticated or otherwise trustworthy input.

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
            // Resolve the requested name against the fixed test-files directory, then
            // canonicalize both paths and confirm the resolved file is still inside that
            // directory. This rejects any ".." traversal or absolute-path override rather
            // than trying to strip or pattern-match the input.
            java.io.File baseDir =
                    new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR)
                            .getCanonicalFile();
            java.io.File requestedFile = new java.io.File(baseDir, param).getCanonicalFile();

            if (!requestedFile.toPath().startsWith(baseDir.toPath())) {
                throw new SecurityException(
                        "Invalid file name: resolves outside the test files directory");
            }

            fileName = requestedFile.getPath();

            // SAST FINDING: CWE-22 (Path Traversal) - a file path is built from request data and opened. Sink is the next statement.
            fos = new java.io.FileOutputStream(requestedFile, false);
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

The original code concatenated `TESTFILES_DIR` and the raw cookie-derived `param` with plain string concatenation, so any `../` sequences in `param` were preserved and interpreted by the filesystem at open time, letting the request escape the intended directory.

The fix resolves the untrusted name against the base directory using `java.io.File`, then calls `getCanonicalFile()` on both the base directory and the resolved target. Canonicalization collapses any `.`/`..` segments and resolves symlinks, giving an absolute, normalized path for each. The code then checks that the canonical target path starts with the canonical base directory path (`Path.startsWith`, which compares whole path segments, not raw string prefixes) before ever opening a stream on it. If the check fails - because `param` contained traversal sequences, an absolute path, or a symlink pointing outside the directory - a `SecurityException` is thrown and caught by the existing `catch (Exception e)` block, so the file is never opened and no output stream escapes the sandboxed directory. Legitimate filenames (the intended use case: a simple name with no directory components) resolve to the same file as before and continue to work unchanged.

This rejects unsafe input outright rather than trying to strip or blocklist `..`, which is the more robust approach: a strip/replace pass can be defeated by encoding tricks or nested sequences, while canonical-path containment is decided by the OS/filesystem itself and cannot be bypassed by clever input formatting.
