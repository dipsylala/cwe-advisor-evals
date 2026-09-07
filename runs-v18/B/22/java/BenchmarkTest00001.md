## Verdict

Exploitable. An attacker can set a cookie value containing `../` sequences that, after URL decoding, allow access to files outside the intended `TESTFILES_DIR` directory. The vulnerability is in the construction and use of the file path at line 73 without validation or canonicalization.

## Source

Cookie value retrieved at line 60-61: `param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8")` from a request cookie named "BenchmarkTest00001". The attacker-controlled cookie value is URL-decoded once and used directly.

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
            // Reject paths with traversal sequences, absolute paths, or null bytes
            if (param.contains("..") || param.startsWith("/") || param.startsWith("\\") || param.contains("\0")) {
                throw new java.io.IOException("Invalid path");
            }

            // Canonicalize the base directory and the candidate path
            java.nio.file.Path baseDir = new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR).toPath().toRealPath();
            java.nio.file.Path candidatePath = baseDir.resolve(param);
            java.nio.file.Path realPath = candidatePath.toRealPath();

            // Verify the resolved path is contained within the base directory
            if (!realPath.startsWith(baseDir)) {
                throw new java.io.IOException("Path traversal attempt detected");
            }

            fileName = realPath.toString();
            fis = new java.io.FileInputStream(fileName);
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

The fix eliminates the path traversal vulnerability by introducing three layers of defence: explicit rejection of suspicious patterns, canonicalization of paths to absolute form, and containment verification.

First, it rejects any `param` value containing `..`, absolute path indicators (`/` or `\`), or null bytes. This provides immediate feedback for clear traversal attempts and serves as a secondary control.

Second, it canonicalizes both the base directory and the candidate path using `Path.toRealPath()`, which resolves symbolic links and relative path references (including `..`) to their true absolute form. This ensures that any path constructed from the user input is converted to its canonical representation, defeating obfuscation attempts.

Third, and most importantly, it verifies the canonicalized path remains within the base directory using `Path.startsWith(Path)`. This comparison operates at the path-component level, preventing false positives from string prefixing (e.g., `/app/uploads-secret` does not match a base of `/app/uploads`). If the resolved path escapes the base directory, an exception is thrown.

The fix preserves the original sink contract: `FileInputStream` is created with the canonicalized path, the same data is read, and the same HTML-encoded output is produced to the response. The exception handling remains unchanged.

## Behaviour changes

The fix replaces the path construction at lines 71-73. Instead of a simple string concatenation, it constructs and validates the path through the Java NIO `Path` API. If the parameter contains traversal sequences or points outside the base directory, an `IOException` is raised, which is caught by the existing exception handler (line 86). The error message is identical in treatment to other exceptions—written to the response writer with HTML encoding.

One additional behaviour change: the `fileName` variable now holds the canonical absolute path instead of the concatenated string. This does not affect output since `fileName` is only used for logging and HTML encoding the response, both of which work identically with the canonical form. The canonical path is more informative for security logging.

No change to arguments, return values, or implicit parameters. The `FileInputStream` constructor receives a string path exactly as before, the data is read identically, and the response writer receives the same encoded output. The only functional difference is the validation that occurs before the file operation, which closes the vulnerability without altering the contract of the sink.

