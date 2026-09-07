## Verdict
CONFIRMED - CWE-79 (Cross-site Scripting). User-controlled input from the HTTP Referer header is written directly to the response body without HTML escaping, allowing arbitrary script injection.

## Source
The vulnerability exists at line 57 where `param` (derived from the user-supplied Referer header at line 45-49, then URL-decoded at line 52) is passed directly to `response.getWriter().format()` without any HTML sanitization. Since the response content type is set to `text/html` at line 42, the unescaped input will be interpreted as HTML/JavaScript by the browser.

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
import org.apache.commons.lang3.StringEscapeUtils;

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
        // FIXED: HTML-escape the user input before writing to response
        response.getWriter().write(StringEscapeUtils.escapeHtml4(param));
    }
}
```

## Explanation
The fix escapes HTML entities in the user-supplied `param` value using Apache Commons Lang's `StringEscapeUtils.escapeHtml4()` method before writing it to the response. This prevents any HTML or JavaScript metacharacters from being interpreted by the browser. Characters like `<`, `>`, `&`, and quotes are converted to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#039;`), ensuring the input is rendered as literal text rather than executable code. The escaped write prevents script injection while preserving the actual data in the response.

`StringEscapeUtils.escapeHtml4()` is the standard approach for HTML output encoding in Java and is available via Apache Commons Lang 3.x, a widely-deployed dependency.
