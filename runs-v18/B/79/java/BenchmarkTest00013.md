## Verdict
exploitable

## Source
`request.getHeaders("Referer")` at line 45 — untrusted HTTP header, attacker-controlled.

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
        // Fixed: Encode untrusted data for HTML output context to prevent XSS
        response.getWriter().println(Encode.forHtml(param));
    }
}
```

## Explanation
The original code at line 57 writes untrusted data from the HTTP Referer header directly to the response body without encoding. An attacker can inject HTML or JavaScript by setting the Referer header to a payload like `"><script>alert('xss')</script>`, which the browser will execute. The fix encodes the untrusted parameter using `org.owasp.encoder.Encode.forHtml()` before writing it to the response, converting any HTML metacharacters (such as `<`, `>`, `&`) into HTML entities, preventing script injection. The OWASP Encoder library, already a dependency in the project (version 1.2.3 in pom.xml), provides context-specific encoding functions—`forHtml()` is the appropriate choice for HTML body content. The change also simplifies the output from `format()` with an unused arguments array to a direct `println()` call.

## Behaviour changes
The original code passed an unused `Object[] obj = {"a", "b"}` array to `format()` and used the Referer header value as a format string. These are both removed: the fixed code writes the encoded parameter value as-is to the output stream without format string processing. This eliminates the format string vulnerability as well. The practical effect is that any format specifiers in a malicious Referer header are now output as literal text (encoded) rather than interpreted as format directives. Since the Referer header is not expected to contain intentional format specifiers, this is not a functional regression.
