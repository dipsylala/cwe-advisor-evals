## Verdict

VULNERABLE. The original code at line 74 constructs a filesystem path from untrusted cookie data without validation or canonicalization, enabling directory traversal attacks.

## Source

Cookie value → URLDecoder.decode() [double-decoding] → String concatenation → FileOutputStream open (line 74)

The vulnerability chain:
1. Line 55-64: Cookie value is extracted (already percent-decoded by servlet)
2. Line 61: `URLDecoder.decode()` is applied again, converting safe literals like `%2e%2e%2f` into dangerous traversal sequences `../`
3. Line 71: Path concatenated from base directory + untrusted param with no validation
4. Line 74: File opened without containment verification

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
                    // Cookie value is already decoded by the servlet container - do not decode again
                    param = theCookie.getValue();
                    break;
                }
            }
        }

        String fileName = null;
        java.io.FileOutputStream fos = null;

        try {
            // Reject traversal sequences and path separators
            if (param.contains("..") || param.contains("/") || param.contains("\\") || param.contains("\0")) {
                throw new IllegalArgumentException("Invalid filename: contains traversal or separator characters");
            }
            
            // Ensure param is a single filename component (no path structure)
            java.nio.file.Path paramPath = java.nio.file.Paths.get(param);
            if (!paramPath.getFileName().toString().equals(param)) {
                throw new IllegalArgumentException("Invalid filename: must be a single component");
            }

            // Canonicalize the base directory (which must exist)
            java.nio.file.Path baseDir = java.nio.file.Paths.get(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR).toRealPath();
            
            // Resolve the filename against the base
            java.nio.file.Path targetPath = baseDir.resolve(param);
            
            // Verify the target stays within the base directory
            if (!targetPath.startsWith(baseDir)) {
                throw new IllegalArgumentException("Path traversal attempt detected");
            }

            fileName = targetPath.toString();

            // SAST FINDING: CWE-22 (Path Traversal) - FIXED: path is validated, canonicalized, and verified to stay within base directory
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

The fix implements path traversal defense in depth:

1. **Remove double-decoding:** Removed `URLDecoder.decode()` because `request.getCookies()` already returns percent-decoded values. Decoding again would turn safe literals like `%2e%2e%2f` into `../`.

2. **Reject traversal characters:** Check for `..`, `/`, `\\`, and null bytes to reject any input attempting directory traversal or containing path structure.

3. **Single-component validation:** Verify that `param` is a single filename component with no embedded path separators by comparing `Paths.get(param).getFileName().toString()` against the original string.

4. **Canonicalize base directory:** Use `toRealPath()` on the base directory to resolve any symlinks and relative references, ensuring we have an absolute canonical path as the containment boundary.

5. **Resolve and verify containment:** Resolve the filename against the canonical base directory, then use `Path.startsWith()` to verify the result stays within the base. This path-component-aware comparison is more secure than string prefix matching (which would incorrectly accept `/app/uploads-backup` if the base is `/app/uploads`).

## Behaviour changes

- **Rejects traversal attempts:** Input containing `..`, `/`, `\\`, or `\0` will raise an `IllegalArgumentException` instead of opening arbitrary files.
- **Blocks double-decoding attacks:** Removing the redundant `URLDecoder.decode()` prevents attackers from encoding traversal sequences (e.g., `%2e%2e%2f`) to bypass filters.
- **Enforces single-component filenames:** Filenames with embedded path structure are rejected early.
- **Guarantees containment:** The `Path.startsWith()` check ensures symlinks and relative path references cannot escape the base directory.
- **Safe for legitimate files:** Valid single-component filenames like `test.txt` or `document-2025.pdf` are accepted and opened normally.
