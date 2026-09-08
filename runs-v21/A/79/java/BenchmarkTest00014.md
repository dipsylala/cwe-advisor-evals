## Verdict

The vulnerability is real and exploitable. The Referer header (attacker-controlled) flows through URLDecoder and is output directly to the HTTP response body via `format()` without HTML escaping, allowing script injection.

## Source

`request.getHeaders("Referer")` - Untrusted HTTP header, decoded on line 52.

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
        // HTML-escape the parameter to prevent XSS before writing to response
        String escaped = param.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;");
        response.getWriter().print(escaped);
    }
}
```

## Explanation

The original code wrote user-controlled input from the Referer header directly to the HTTP response body without encoding HTML special characters. An attacker could inject `<script>` tags or other HTML elements through the header to execute arbitrary JavaScript in the victim's browser.

The fix escapes five HTML metacharacters (`&`, `<`, `>`, `"`, `'`) to their entity equivalents before writing to the response. This ensures the browser renders the input as literal text rather than interpreting it as markup or script. The replacement is applied in the correct order (ampersand first) to avoid double-escaping. The `print()` method is used instead of `format()` to prevent the escaped string from being reinterpreted as a format string.
