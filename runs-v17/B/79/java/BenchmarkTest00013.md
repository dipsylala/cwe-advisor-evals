## Verdict
exploitable

## Source
Line 45-48: Untrusted data from HTTP request headers via `request.getHeaders("Referer")`

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
        // FIXED: Apply HTML encoding to neutralize XSS - param is untrusted user input from request headers
        response.getWriter().format(java.util.Locale.US, "%s", Encode.forHtml(param));
    }
}
```

## Explanation
The vulnerability occurs because user-controlled data from the HTTP Referer header is written directly to the response body without encoding. At line 57, the format method outputs the param string as-is. An attacker can inject malicious HTML or JavaScript (e.g., `<script>alert('XSS')</script>`) through the Referer header, which executes in victims' browsers. The fix applies OWASP Java Encoder's `Encode.forHtml()` to perform context-appropriate HTML entity encoding on the untrusted param value before writing it to the response. This transforms dangerous characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, etc.), ensuring the data is rendered as text content rather than executable code. The format string is changed to a fixed pattern (`"%s"`) with the encoded value as an argument to prevent format string injection.

## Behaviour changes
- Added import for `org.owasp.encoder.Encode` (required for the HTML encoding function)
- Changed line 57 from `response.getWriter().format(java.util.Locale.US, param, obj)` to `response.getWriter().format(java.util.Locale.US, "%s", Encode.forHtml(param))` to encode output and use a fixed format string
- The obj array is no longer passed to format(); this is not a functional regression because it was not used in the original output anyway (the original format call would have simply ignored unused arguments)
