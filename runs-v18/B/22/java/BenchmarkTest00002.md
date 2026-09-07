## Verdict

VULNERABLE to CWE-22 (Path Traversal). An attacker can craft a cookie value like `%2e%2e/etc/passwd` which, after URLDecoder.decode(), becomes `../etc/passwd`, allowing escape from TESTFILES_DIR when passed to FileOutputStream. No path canonicalization or containment validation is present.

## Source

Cookie value retrieved at line 61 without proper validation:
```
param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
```

Concatenated into file path at line 71:
```
fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;
```

Opened at line 74 (the sink):
```
fos = new java.io.FileOutputStream(fileName, false);
```

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
                    // Use cookie value directly; do not re-decode
                    param = theCookie.getValue();
                    break;
                }
            }
        }

        String fileName = null;
        java.io.FileOutputStream fos = null;

        try {
            String baseDir = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR;
            java.nio.file.Path basePath = new java.io.File(baseDir).toPath().toRealPath();

            // Reject if param contains traversal sequences or path separators
            if (param.contains("..") || param.contains("/") || param.contains("\\") || param.contains("\0")) {
                throw new java.io.IOException("Invalid filename: contains traversal or separator characters");
            }

            // Resolve candidate path against base directory
            java.nio.file.Path candidatePath = basePath.resolve(param);

            // Canonicalize and verify containment; handle case where file doesn't exist yet
            try {
                java.nio.file.Path realPath = candidatePath.toRealPath();
                if (!realPath.startsWith(basePath)) {
                    throw new java.io.IOException("Path traversal attempt");
                }
            } catch (java.nio.file.NoSuchFileException e) {
                // File doesn't exist yet; verify parent directory is within base
                java.nio.file.Path parentPath = candidatePath.getParent();
                if (parentPath == null || !parentPath.toRealPath().startsWith(basePath)) {
                    throw new java.io.IOException("Path traversal attempt");
                }
            }

            fileName = candidatePath.toString();
            // SAST FINDING FIXED: CWE-22 (Path Traversal) - path is now canonicalized and containment-verified
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

The fix closes the path traversal vulnerability through three mechanisms:

1. **Remove unnecessary decoding** (line 61): Deleted the `URLDecoder.decode()` call. Cookie values from `request.getCookies()` are raw HTTP header values, not pre-decoded by the container. Re-decoding a literal cookie like `BenchmarkTest00002=FileName` is unnecessary, and re-decoding untrusted input manufactures exploits: an attacker sending `%2e%2e/etc/passwd` would have it decoded into `../etc/passwd`.

2. **Canonicalize and validate** (lines 74-86): Before opening the file, the path is canonicalized using `Path.toRealPath()`, which resolves symlinks and relative references (`.`, `..`) to absolute form. For a new file that doesn't exist yet, the parent directory is canonicalized instead (the guidance for write destinations where the target hasn't been created).

3. **Enforce containment** (lines 77-78, 83-86): After canonicalization, `Path.startsWith()` verifies the resolved path stays within `basePath`. This is stricter than string prefix checks and uses path-component-aware comparison, preventing escapes like `basePath + "/../sibling"` or symlink-based traversal. Explicit rejection of `../`, `/`, `\\`, and null bytes in the input prevents both encoded and raw traversal sequences.

The fix preserves the original exception handling contract: invalid paths trigger an exception, which is caught and logged on line 88, preventing the file operation from succeeding.

## Behaviour changes

The fixed code rejects path values that:
- Contain `..` sequences (either as literal input or URL-encoded as `%2e%2e`)
- Contain path separators (`/`, `\`) allowing multi-level access
- Contain null bytes
- Would resolve outside the base directory when canonicalized

Valid filenames like `FileName`, `document.txt`, or `2024-report` continue to work. Attackers can no longer escape `TESTFILES_DIR` by supplying traversal sequences in the cookie.
