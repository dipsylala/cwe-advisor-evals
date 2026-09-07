## Verdict
exploitable

## Source
The `Referer` request header (line 45-48), which is untrusted attacker-controlled data obtained via `request.getHeaders("Referer")`.

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
import org.owasp.encoder.Encode;

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
        // Fixed: HTML encode the parameter to prevent XSS injection in the response body
        response.getWriter().println(Encode.forHtml(param));
    }
}
```

## Explanation

The vulnerability occurs at line 57, where untrusted data from the `Referer` HTTP header is written directly to the response body via `response.getWriter().format(param, obj)` without any HTML encoding. An attacker can craft a malicious `Referer` header containing XSS payloads (e.g., `"><script>alert('XSS')</script>`) that will be reflected in the HTML response and executed in the victim's browser.

The fix replaces the unencoded format call with `response.getWriter().println(Encode.forHtml(param))`, using OWASP Java Encoder's `Encode.forHtml()` method to HTML-encode the parameter before output. This encoding converts dangerous characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents, preventing the browser from interpreting the payload as executable code. The fix also requires adding the import statement `import org.owasp.encoder.Encode;` to access the encoder class.

## Behaviour changes

The `obj` array defined at line 55 is no longer used; it was only present as an argument to the original `format()` call and serves no purpose in the fixed code. The output now uses `println()` instead of `format()`, which appends a newline character at the end. This is a minor difference but ensures clean line-delimited output, which is appropriate for HTTP responses.
