## Verdict

**exploitable** (confidence: high)

- CWE: CWE-79 (Improper Neutralization of Input During Web Page Generation / Cross-Site Scripting)
- Location: `BenchmarkTest00013.java`, line 57 (`response.getWriter().format(java.util.Locale.US, param, obj)`)

## Source

`request.getHeaders("Referer")` (line 45) - the first `Referer` header value from the incoming HTTP request, fully attacker-controlled. It is URL-decoded at line 52 (`java.net.URLDecoder.decode(param, "UTF-8")`), which does not remove or encode HTML metacharacters - it only reverses percent-encoding, so a payload sent as `%3Cscript%3E...` arrives at the sink as literal `<script>...`.

## Fix

### File: BenchmarkTest00013.java

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
import org.owasp.encoder.Encode;

@WebServlet(value = "/xss-00/BenchmarkTest00013")
public class BenchmarkTest00013 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("Referer");

        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement(); // just grab first element
        }

        // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        response.setHeader("X-XSS-Protection", "0");
        Object[] obj = {"a", "b"};
        response.getWriter().format(java.util.Locale.US, Encode.forHtml(param), obj);
    }
}
```

**Library recommendation:** `org.owasp.encoder:encoder` (class `org.owasp.encoder.Encode`), used here via `Encode.forHtml()`. The loaded guidance does not carry a minimum safe version for this artifact - resolve and pin the version through SCA/dependency-check tooling before merging, rather than from this proposal. Add the dependency to the project's build file (e.g. `pom.xml`); no manifest file was present in this case directory to edit directly.

## Explanation

The response body is HTML (`Content-Type: text/html`), and the sink writes the attacker-controlled, URL-decoded `Referer` header directly into that body with no encoding, so a payload such as `<script>...</script>` in the header is emitted verbatim and executes in the victim's browser. The fix wraps the untrusted value in `Encode.forHtml(param)` immediately before it reaches the sink, converting `<`, `>`, `&`, `"`, `'` and other HTML-significant characters into their entity equivalents so the payload renders as inert text instead of markup. This is the context-appropriate encoding the knowledge base prescribes for output landing in an HTML body (`Encode.forHtml()`, not the attribute/JS/URL/CSS variants, since this is body content, not an attribute or script context).

## Behaviour changes

- The value passed as the format-string argument to `PrintWriter.format(Locale, String, Object...)` is now `Encode.forHtml(param)` instead of raw `param`. This is the encoding fix itself, not incidental scope creep.
- `obj` (`{"a", "b"}`) is passed unchanged and is still only consumed if the format string contains matching `%s`-style conversions - encoding does not introduce `%` characters, so this remains exactly as likely (or unlikely) to be invoked as before the fix.
- No other arguments, return-value handling, or control flow changed. `format()`'s return value was already discarded before the fix and remains so; `Locale.US` is unchanged; failure behavior (an `IllegalFormatException` if `param` happens to contain a malformed conversion specifier) is preexisting and unaffected by HTML-encoding the string, since encoding does not alter or introduce `%` characters.

**Verification:** Copied the fixed file to a scratch directory and ran `javac` against it standalone (no project classpath available in this environment). All reported diagnostics were unresolved-package/symbol errors for `javax.servlet.*` and `org.owasp.encoder.*` - expected, since neither the servlet API nor the OWASP Encoder jar is on the ad hoc classpath - with no diagnostics inside the method body concerning argument count, types, or the new `Encode.forHtml(param)` call itself. This confirms the file is syntactically well-formed; full type/dependency resolution requires the project's actual build (with `org.owasp.encoder:encoder` on the classpath), which was not available here.

**Assumptions:** The class `org.owasp.encoder.Encode` and its `forHtml(String)` method are taken from the loaded `cwe/79/java/INDEX.md` guidance verbatim (not independently verified against the artifact, since no classpath/registry access was available in this environment) - confidence is otherwise high because the guidance names this exact API for HTML-body encoding.
