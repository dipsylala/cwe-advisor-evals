## Verdict

- **cwe_id**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory / Path Traversal)
- **location**: `BenchmarkTest00002.java`, line 74 (`fos = new java.io.FileOutputStream(fileName, false);`)
- **verdict**: exploitable
- **confidence**: high

## Source

- **Source**: the `BenchmarkTest00002` cookie value, read from `request.getCookies()` (line 60) and URL-decoded with `java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8")` (line 61) into `param`. This is attacker-controlled - a client sets its own cookie value.
- **Data flow**: `param` flows unchanged into `fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param` (line 71), a plain string concatenation with no validation or canonicalization.
- **Sink**: `fileName` is passed directly to `new java.io.FileOutputStream(fileName, false)` (line 74), which creates or truncates the named file. A cookie value such as `../../../../tmp/evil` (or an absolute path) lets the request overwrite or create a file anywhere the server process can write, outside the intended `TESTFILES_DIR` root.

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
            // Canonicalize the base directory (it already exists, so toRealPath() resolves
            // any symlink in it), then require the untrusted cookie value to name a single
            // file directly inside that directory - no path separators and no dot-dot -
            // before it is combined into a path at all. Paths.get() itself rejects an
            // embedded NUL character by throwing InvalidPathException.
            java.nio.file.Path baseDir =
                    java.nio.file.Paths.get(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR)
                            .toRealPath();

            java.nio.file.Path requestedName = java.nio.file.Paths.get(param).getFileName();
            if (requestedName == null || !requestedName.toString().equals(param)) {
                throw new java.io.IOException("Invalid file name: " + param);
            }

            java.nio.file.Path resolvedPath = baseDir.resolve(param).normalize();
            if (!resolvedPath.startsWith(baseDir)) {
                throw new java.io.IOException("Invalid file name: " + param);
            }

            fileName = resolvedPath.toString();

            // SAST FINDING: CWE-22 (Path Traversal) - a file path is built from request data and opened. Sink is the next statement.
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

The write target does not exist yet at request time, so `toRealPath()` cannot be applied to the candidate file itself (per the CWE-22 Java guidance, an upload/write-style sink must canonicalize the parent directory instead). The fix canonicalizes `Utils.TESTFILES_DIR` once via `toRealPath()`, which resolves any symlink in that already-existing root, and treats the cookie-derived `param` as the name of a single file that must live directly inside it. `Paths.get(param).getFileName()` is compared against `param` itself: if the value contains a path separator or is an absolute path, the parsed file-name component differs from the full string and the request is rejected before any path is built. The remaining candidate is resolved under the canonicalized base with `resolve(param).normalize()` and checked with `Path.startsWith(Path)` (component-aware, not a string prefix check), which also catches a value like `..` that passes the single-component test but would otherwise walk out of the root. Only the resulting `resolvedPath` - never the raw `TESTFILES_DIR + param` concatenation - is used for both the `FileOutputStream` call and the message echoed back to the client, so the sink and the diagnostic output agree on the same validated value. This closes the traversal: no cookie value can make `fileName` resolve to a path outside `TESTFILES_DIR`.

## Behaviour changes

- `fileName` is now built with `Path.resolve()`/`normalize()` instead of raw string concatenation. If `TESTFILES_DIR` already ends with a path separator (the concatenation pattern in the original code implies it does) the resulting path is identical for any legitimate single-segment filename; `resolve()` additionally guarantees a correct separator even if it did not, which cannot produce a different legitimate outcome, only avoid a latent malformed-path bug.
- A cookie value containing a path separator, `..`, or an absolute path is now rejected with an `IOException` before any file operation is attempted, where the original code would previously have let `FileOutputStream` attempt to open the traversed path. This is the intended effect of the fix, not incidental.
- On a rejected (invalid) file name, `fileName` remains `null` at the point the `catch` block logs `"Couldn't open FileOutputStream on file: 'null'"`, whereas the original code, if it reached an exception for any other reason, would have logged the raw concatenated path. This only affects the invalid-filename diagnostic message content, not control flow or the response sent to the client.
- No other differences: cookie reading, URL-decoding of the cookie value, response content type, the `finally` block closing `fos`, and exception handling are unchanged.

**Assumption**: `Utils.TESTFILES_DIR` is not present in the supplied call chain (it lives in an OWASP Benchmark helper class outside this file) and is assumed to name a directory that exists at runtime, per the language guidance's requirement that the canonicalized parent already exist for `toRealPath()` to succeed - consistent with the original code already using it as an existing base for both `doGet`'s dispatcher include path and `doPost`'s write target.

**Library recommendation**: none. The fix uses only `java.nio.file` (JDK standard library); no third-party dependency is introduced or changed.

**Verification**: the fixed file was copied to a scratch directory (`org/owasp/benchmark/testcode/BenchmarkTest00002.java` under a matching package layout) and compiled with `javac` (JDK 26, `javac -d out org/owasp/benchmark/testcode/BenchmarkTest00002.java`). The only diagnostics were "package does not exist" / "cannot find symbol" errors for `javax.servlet.*`, `org.owasp.benchmark.helpers.Utils`, and `org.owasp.esapi.ESAPI` - all pre-existing external dependencies unavailable in the scratch environment, not part of this fix. No errors were raised against any of the newly introduced `java.nio.file.Path` / `Paths` calls (`toRealPath()`, `resolve()`, `normalize()`, `startsWith()`, `getFileName()`), confirming they are used with correct signatures against the real JDK.
