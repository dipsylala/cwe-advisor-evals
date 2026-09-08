## Verdict

Confirmed. The `Referer` request header is URL-decoded and then passed directly as the *format string* argument to `PrintWriter.format(Locale, String, Object...)`. Whatever the header contains is written verbatim into the HTTP response body with no HTML encoding, so an attacker-controlled `Referer` value such as `<script>alert(1)</script>` is reflected straight into the page and executes in the victim's browser (reflected XSS).

## Source

`request.getHeaders("Referer")` in `doPost` (`BenchmarkTest00013.java:45-48`) reads the attacker-controlled `Referer` header. It is URL-decoded at line 52 and then flows unmodified into the sink at line 57.

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
        // Fixed: never use attacker-controlled data as the format string itself, and
        // HTML-encode it before it reaches the response body so any markup/script it
        // contains is rendered as inert text instead of being interpreted by the browser.
        response.getWriter().format(java.util.Locale.US, "%s", Encode.forHtml(param));
    }
}
```

## Explanation

The original code used the raw, attacker-controlled `param` value as the *format string* passed to `Formatter`/`PrintWriter.format`, so its contents were written into the HTML response byte-for-byte with no encoding at all - a classic reflected XSS sink, and additionally a format-string hazard since any `%` sequences in the header would be interpreted as format specifiers rather than literal text.

The fix addresses both problems at once:

- The literal format string is now the fixed, developer-controlled `"%s"`, so user input can never be interpreted as format directives.
- `param` is passed as a *value* to `%s`, run through `org.owasp.encoder.Encode.forHtml()` (the OWASP Java Encoder library, `org.owasp.encoder:encoder`) first. This performs contextual HTML entity encoding, turning `<`, `>`, `&`, `"`, `'` and similar characters into their inert HTML entity equivalents so any injected markup or script renders as visible text instead of being parsed by the browser as executable HTML.
- The response is still emitted through the same `getWriter().format(...)` call and `obj` is left untouched, so the change is limited to closing the injection rather than restructuring unrelated code.

Because the encoding happens immediately before the value is written to the response body (the sink), this holds regardless of what the `Referer` header contains, including additional `%`-format sequences, HTML tags, or `javascript:` URIs.
