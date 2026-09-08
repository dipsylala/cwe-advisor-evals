## Verdict

Confirmed. The `Referer` request header is decoded and then written directly into the HTTP response body via `response.getWriter().format(param, obj)`. `param` is fully attacker-controlled (an HTTP request header) and reaches the response with no HTML-encoding, so a `Referer` value such as `<script>alert(1)</script>` is reflected verbatim into the page and executes in the victim's browser - reflected Cross-Site Scripting (CWE-79). Using the untrusted value as the format string itself is a secondary problem: any `%` conversion sequence in the header (e.g. `%s`, `%n`) is interpreted by `Formatter`, which can throw `IllegalFormatException` (denial of service) or unexpectedly consume/emit the `obj` array contents.

## Source

`request.getHeaders("Referer")` (`HttpServletRequest`) at line 45, read via `headers.nextElement()` at line 48 and URL-decoded at line 52. This value flows unmodified into `response.getWriter().format(param, obj)` at line 57, which is the sink.

## Fix

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
        Object[] obj = {"a", "b"};
        // Encode for the HTML body context and write the value literally instead of using
        // attacker-controlled data as a Formatter pattern.
        response.getWriter().write(encodeForHtml(param));
    }

    /**
     * Minimal HTML-body encoder: escapes the characters that let attacker-controlled text break
     * out of a text node and inject markup or attributes.
     */
    private static String encodeForHtml(String input) {
        if (input == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '&':
                    sb.append("&amp;");
                    break;
                case '<':
                    sb.append("&lt;");
                    break;
                case '>':
                    sb.append("&gt;");
                    break;
                case '"':
                    sb.append("&quot;");
                    break;
                case '\'':
                    sb.append("&#x27;");
                    break;
                case '/':
                    sb.append("&#x2F;");
                    break;
                default:
                    sb.append(c);
            }
        }
        return sb.toString();
    }
}
```

## Explanation

The fix removes both problems at the sink in one change:

- `param` is now HTML-encoded (`&`, `<`, `>`, `"`, `'`, `/`) before it reaches the response body, so any markup or attribute-breaking characters in the `Referer` header are rendered as inert text instead of being parsed as HTML/script by the browser.
- The write no longer goes through `Formatter.format(String, Object...)` with attacker-controlled data as the pattern argument. Writing the encoded string literally with `write(...)` removes the `%`-directive interpretation risk entirely, since encoded output is never treated as a format string.

The `obj` array and the header-reading/URL-decoding logic are left untouched, since they are not part of the vulnerability - only the final write needed to change. Testing: send a request with `Referer: <script>alert(1)</script>` (URL-encoded) and confirm the response body contains `&lt;script&gt;alert(1)&lt;/script&gt;` rather than an executable `<script>` tag; also send `Referer: %s%n` and confirm no `IllegalFormatException` and no substitution occurs.
