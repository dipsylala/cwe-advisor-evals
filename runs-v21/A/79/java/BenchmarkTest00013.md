## Verdict
CONFIRMED - CWE-79 Cross-site Scripting vulnerability. Untrusted data from the Referer header is written to the HTTP response body without HTML escaping.

## Source
The vulnerable data originates from the `Referer` request header (line 45-48), is URL-decoded (line 52), and written directly to the response body without escaping (line 57).

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

        // HTML escape the parameter to prevent XSS
        param = escapeHtml(param);

        response.setHeader("X-XSS-Protection", "0");
        Object[] obj = {"a", "b"};
        response.getWriter().write(param);
    }

    /**
     * Escapes HTML special characters to prevent XSS attacks.
     */
    private static String escapeHtml(String input) {
        if (input == null) {
            return null;
        }
        return input.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }
}
```

## Explanation
The vulnerability existed because untrusted user input (Referer header) was passed directly to `response.getWriter().format()` and written to the HTTP response body without HTML escaping. This allows an attacker to inject arbitrary HTML and JavaScript.

The fix:
1. Added an `escapeHtml()` helper method that escapes the five critical HTML special characters (`&`, `<`, `>`, `"`, `'`) to their respective HTML entities.
2. Applied HTML escaping to `param` before writing it to the response (line 56).
3. Changed from `format()` with the unsanitized parameter as a format string to `write()` with the escaped output, eliminating both the format string vector and the XSS vector.

The escaping ensures that any HTML or JavaScript in the Referer header is rendered as literal text rather than interpreted by the browser.
