## Verdict

Exploitable. CWE-22 (Path Traversal), Java, `BenchmarkTest00001.java` line 73.

## Source

`doPost` reads the incoming `HttpServletRequest`'s cookies (`request.getCookies()`), finds the cookie named `BenchmarkTest00001`, and takes its value: `param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8")`. A cookie value is attacker-controlled - it is sent by the client and not validated or constrained before use.

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

            // Canonicalize the configured base directory once, then resolve the
            // requested name against it and require the result to stay inside it.
            java.nio.file.Path baseDir =
                    java.nio.file.Paths.get(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR)
                            .toRealPath();

            if (param.indexOf('\0') >= 0 || java.nio.file.Paths.get(param).isAbsolute()) {
                throw new IOException("Invalid file path: " + param);
            }

            java.nio.file.Path resolved = baseDir.resolve(param).normalize();
            if (!resolved.startsWith(baseDir)) {
                throw new IOException("Invalid file path: " + param);
            }

            // toRealPath() follows symlinks and requires the target to exist, which a
            // readable test file already must.
            java.nio.file.Path realResolved = resolved.toRealPath();
            if (!realResolved.startsWith(baseDir)) {
                throw new IOException("Invalid file path: " + param);
            }

            fileName = realResolved.toString();
            fis = new java.io.FileInputStream(realResolved.toFile());
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

The vulnerable code built `fileName` by concatenating a fixed base directory with the attacker-controlled cookie value and passed that raw, unvalidated string straight to `FileInputStream`/`File`, so a value such as `../../../../etc/passwd` (or its `..%2f` variants, which `URLDecoder` further decodes) could escape the intended test-files directory. The fix keeps the original `fileName = TESTFILES_DIR + param` line for logging/error-message parity, then independently derives the value actually used to open the file: it canonicalizes the base directory once with `Path.toRealPath()`, rejects an absolute `param` or an embedded null byte outright (an absolute path passed to `Path.resolve()` discards the base entirely, so this must be checked before resolving), resolves `param` against the canonicalized base and normalizes it, and requires that result to be contained under the base via `Path.startsWith(Path)` (object comparison, not a string prefix). It then re-canonicalizes the resolved candidate with a second `toRealPath()` call and re-checks containment, so a symlink planted inside the base directory that points outside it is also caught. Only the resulting `realResolved` path - resolved exactly once and reused - is passed to `FileInputStream`. This matches the language guidance's primary defence ("resolve the candidate with `toRealPath()` and confirm the result is inside the base directory with `Path.startsWith(Path)`") and its remediation steps (reject absolute paths/null bytes before resolving, canonicalize with `toRealPath()`, compare `Path` objects, no redundant `..` substring test).

## Behaviour changes

- A request whose cookie value resolves outside `TESTFILES_DIR` (traversal, absolute path, or a symlink escaping the base) now throws `IOException` before any file is opened, which is caught by the existing `catch (Exception e)` block - the same error-handling path the original code used for a nonexistent-file `FileNotFoundException`. Client-visible behaviour (a "Problem getting FileInputStream" message) and server-side logging (`fileName` is set before validation, so the attempted path still appears in the `System.out.println`) are both preserved for this case.
- On a legitimate request, the value echoed back in the "beginning of file" response and passed to `FileInputStream` is the canonical (`toRealPath()`) form of the path rather than the raw `TESTFILES_DIR + param` concatenation. Both denote the same file; this is a representational difference introduced by the required canonicalize-then-open pattern, not a functional one.
- No other arguments, return values, or discarded output were changed; the `finally` block, cookie-setting `doGet` method, and exception handling are untouched.

## Assumptions

- `org.owasp.benchmark.helpers.Utils.TESTFILES_DIR` is not in the single-file call chain provided; it is treated as a server-controlled constant naming an existing base directory (consistent with its use as a fixed prefix in the original code), so canonicalizing it with `toRealPath()` is expected to succeed at request time.
- No indirect-reference (ID-to-filename) mapping infrastructure exists in the provided code, so the guidance's alternative primary defence - canonicalize with `toRealPath()` and verify containment with `Path.startsWith(Path)` - was applied instead, as the guidance itself offers this as an equally primary option.
- `java.nio.file.Path`, `Paths`, `Path.toRealPath()`, `Path.resolve()`, `Path.normalize()`, `Path.startsWith()`, and `Path.toFile()` are all JDK standard library (`java.nio.file`); no new third-party dependency was introduced.
- Verification: compiled the fixed file with `javac` (JDK 26) against minimal local stubs of the missing `javax.servlet.*`, `org.owasp.esapi.*`, and `org.owasp.benchmark.helpers.Utils` types (none of which are available in this environment) in an isolated scratch directory - not the case directory. Compilation succeeded with only a pre-existing, unrelated deprecation note on `URLDecoder.decode(String,String)` that is present in the original file too.
