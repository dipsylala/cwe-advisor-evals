## Verdict

Exploitable. CWE-79 (Cross-Site Scripting), confidence: high.

## Source

`request.getHeaders("Referer")` in `doPost` (line 45) - the first `Referer` header value, URL-decoded at line 52 (`java.net.URLDecoder.decode(param, "UTF-8")`). The `Referer` header is attacker-controlled: a client can send any value, and URL-decoding it does not neutralize HTML metacharacters.

## Fix

Location of sink: `BenchmarkTest00014.java` line 57, `response.getWriter().format(param, obj)`.

The tainted `param` is passed as the *format string* to `PrintWriter.format(String, Object...)`, not merely as an argument. Every literal character in `param` - including `<`, `>`, `"`, `'` - is copied verbatim into the response body; only `%`-conversion sequences are treated specially. This means the entire attacker-supplied header is written unencoded into an HTML response, and passing untrusted data as a format template is itself unsafe regardless of encoding, since it can also be crafted to trigger `IllegalFormatException` (malformed conversions) against the unrelated `obj` array.

The fix applies OWASP Java Encoder's `Encode.forHtml()` (per `cwe/79/java/INDEX.md`) to the value at the point it is written into the HTML body, and writes it as literal data via `PrintWriter.write(String)` instead of through `format()`. This removes both the missing-encoding weakness and the underlying unsafe pattern of treating untrusted input as a format template. The dummy `Object[] obj = {"a", "b"}` array existed only to satisfy `format()`'s varargs parameter and has no other use in the method, so it is removed along with the sink it supported.

Library recommendation: `org.owasp.encoder:encoder`, class `org.owasp.encoder.Encode`. The loaded guidance does not carry a minimum safe version, so none is asserted here - resolve and pin the version through SCA/dependency-check tooling before merging. No build manifest (e.g. `pom.xml`) is present in this case's file set to show an edit for; add the dependency to whatever build file governs this module.

### File: BenchmarkTest00014.java

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

@WebServlet(value = "/xss-00/BenchmarkTest00014")
public class BenchmarkTest00014 extends HttpServlet {

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
        // Encode the untrusted header value for the HTML body context and write it
        // as literal data rather than as a Formatter template (CWE-79 fix).
        response.getWriter().write(org.owasp.encoder.Encode.forHtml(param));
    }
}
```

## Explanation

`param` is derived from the `Referer` request header, which is fully attacker-controlled, and is URL-decoded without any HTML encoding before reaching the sink. The original code fed it directly into `PrintWriter.format(param, obj)` as the format string, so every character of the header - including markup and script tags - was written verbatim into the `text/html` response body. The fix wraps the value in `org.owasp.encoder.Encode.forHtml()` before writing it, converting `<`, `>`, `&`, `"`, and `'` into their HTML entity equivalents so the browser renders the header's content as inert text rather than parsing it as markup or script, and it writes the result with `PrintWriter.write(String)` so the value is never interpreted as a format template.

## Behaviour changes

- `format(param, obj)` replaced with `write(Encode.forHtml(param))`: required to stop treating untrusted input as a format string, which is the sink itself.
- `Object[] obj = {"a", "b"}` removed: it had no purpose other than satisfying `format()`'s vararg parameter; removing the vulnerable `format()` call removes its only consumer.
- Output content: previously any `%`-conversion sequences in the Referer value (e.g. `%1$s`, `%2$s`) would have been substituted with `"a"`/`"b"`; the fixed code no longer performs any substitution and instead writes the (HTML-encoded) literal header value. This is a behavioural difference from the original but not from any legitimate use of this endpoint, since `format()` was never given a fixed, safe template - the "template" was the untrusted value itself.
- Failure behaviour: the original could throw an unchecked `IllegalFormatException` (e.g. `MissingFormatArgumentException`, `UnknownFormatConversionException`) if the Referer header contained a malformed `%` conversion, which the servlet container would turn into a 500 response. The fixed code performs no format parsing and cannot throw for this reason. This is a direct consequence of removing the unsafe format-as-sink pattern.
- Return value: `format()` returns the `PrintWriter` (discarded in the original); `write()` returns `void`. No caller used the discarded return value, so this has no observable effect.

## Verification

Compiled the fixed file with `javac` (JDK 26) against minimal stub definitions of `javax.servlet.*` (`HttpServlet`, `HttpServletRequest`, `HttpServletResponse`, `ServletException`, `WebServlet`) and `org.owasp.encoder.Encode` reproducing the real APIs' method signatures (`request.getHeaders(String): Enumeration<String>`, `response.getWriter(): PrintWriter`, `Encode.forHtml(String): String`) in a scratch directory outside the codebase. Compilation succeeded with no errors or warnings, confirming `PrintWriter.write(String)` and `Encode.forHtml(String)` are used with valid signatures and the file is otherwise syntactically and referentially sound. The real `org.owasp.encoder:encoder` jar was not available in this environment, so the exact library API surface (method name and signature `Encode.forHtml(String)`) was verified against the loaded guidance (`cwe/79/java/INDEX.md`) rather than the actual dependency; this is recorded as an assumption below.

## Assumptions

- `org.owasp.encoder.Encode.forHtml(String)`'s exact signature was taken from the loaded guidance rather than compiled against the real `encoder` jar (unavailable in this environment); confidence lowered accordingly for that one name.
- No build manifest (`pom.xml`/`build.gradle`) was present among the case files, so the `org.owasp.encoder:encoder` dependency addition is described but not shown as a manifest edit.
- The dummy `Object[] obj` array and the choice of `format()` over `write()`/`print()` in the original are treated as incidental to the OWASP Benchmark test harness rather than behaviour depended on elsewhere, since `obj` is local, unused outside this method, and not read back by any caller.
