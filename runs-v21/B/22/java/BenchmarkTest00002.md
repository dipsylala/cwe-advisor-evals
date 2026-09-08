## Verdict

Path Traversal (CWE-22) confirmed. The cookie value is decoded and concatenated to a base directory path without validation, then passed directly to FileOutputStream. An attacker can supply a cookie value containing `../` sequences or absolute paths to escape the intended directory.

## Source

Cookie source: `request.getCookies()` (line 55)
- Extracted value: `theCookie.getValue()` (line 61)
- Decoded: `java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8")` (line 61)
- Concatenated: `org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param` (line 71)
- Sink: `new java.io.FileOutputStream(fileName, false)` (line 74)

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
                    param = theCookie.getValue();
                    break;
                }
            }
        }

        String fileName = null;
        java.io.FileOutputStream fos = null;

        try {
            // Reject absolute paths and null bytes
            if (param.startsWith("/") || param.startsWith("\\") || param.contains("\0")) {
                throw new IllegalArgumentException("Invalid file name");
            }

            // Get the base directory path
            java.nio.file.Path baseDir =
                    java.nio.file.Paths.get(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR);

            // Canonicalize the base directory
            java.nio.file.Path canonicalBase = baseDir.toRealPath();

            // Verify that the filename doesn't contain path separators or relative components
            java.nio.file.Path fileNamePath = java.nio.file.Paths.get(param);
            java.nio.file.Path fileNameParent = fileNamePath.getParent();
            if (fileNameParent != null && !fileNameParent.toString().equals(".")) {
                throw new IllegalArgumentException("File name cannot contain path separators");
            }

            // Construct the full path
            java.nio.file.Path fullPath = canonicalBase.resolve(param);

            // Normalize to resolve . and .. references
            java.nio.file.Path normalizedPath = fullPath.normalize();

            // Verify the normalized path stays within the base directory
            if (!normalizedPath.startsWith(canonicalBase)) {
                throw new IllegalArgumentException("Path traversal attempt detected");
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

The fix closes the path traversal vulnerability by validating the filename before using it to construct a file path. The key changes are:

1. **Remove URLDecoder.decode()**: The original code called `URLDecoder.decode()` on the cookie value, which reintroduces percent-encoding that may have prevented traversal (e.g., `%2e%2e%2f` becomes `../`). Cookie values from `request.getCookies()` are already in their final form and should not be re-decoded. Per the CWE-22 guidance, a second decoding step can manufacture traversal from an inert literal.

2. **Reject absolute paths and null bytes**: Before any path processing, reject values that start with `/`, `\`, or contain null bytes, which are indicators of malicious input.

3. **Canonicalize the base directory**: Call `toRealPath()` on the base directory (which exists) to get its absolute canonical form, resolving any symlinks. This establishes the secure boundary.

4. **Validate filename is a single component**: For a write operation where the target doesn't exist yet, verify that the supplied filename parameter contains no path separators by checking that `Paths.get(param).getParent()` is null or `.`. This prevents values like `../admin` or `etc/passwd` from being accepted.

5. **Normalize and verify containment**: Construct the full path, normalize it to resolve `.` and `..` references, and verify that the resulting absolute path starts with the canonical base directory using `Path.startsWith()`. This is a path-component-aware comparison that safely rejects sibling directories.

The fix uses Java NIO's `java.nio.file.Path` API, which provides safer path operations than string concatenation. The containment check uses `Path.startsWith(Path)` rather than string prefix comparison, which prevents acceptance of sibling directories like `/app/uploads-backup` when the base is `/app/uploads`.

## Behaviour changes

- **Invalid filenames rejected**: Attempts to traverse directories (e.g., `../`, `../../../etc/passwd`, or absolute paths) now throw an `IllegalArgumentException` instead of being passed to the filesystem.
- **Error handling**: The exception is caught by the existing `catch (Exception e)` block, which logs the error to stdout. This preserves the original error handling behavior while preventing file access.
- **Null bytes rejected**: Values containing null bytes are now rejected, hardening against null byte injection attacks.
- **URLDecoder removed**: The cookie value is used as-is without additional URL decoding, which may change behavior if clients are sending percent-encoded values. However, this is the correct and safer behavior per servlet security guidance.
