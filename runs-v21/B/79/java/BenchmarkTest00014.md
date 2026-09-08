## Verdict

exploitable

## Source

Untrusted HTTP Referer header obtained via `request.getHeaders("Referer")` (line 45), extracted to variable `param` (line 48), URL-decoded (line 52), and written to the HTTP response without HTML encoding.

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
        // SAST FINDING: CWE-79 (Cross-site Scripting) - request data is written into the HTTP response body. Sink is the next statement.
        response.getWriter().format(Encode.forHtml(param), obj);
    }
}
```

## Explanation

The untrusted Referer header value in `param` is written directly to an HTML response without encoding, allowing an attacker to inject arbitrary HTML or JavaScript. The fix applies HTML entity encoding using `Encode.forHtml()` from the OWASP Java Encoder library (artifact `org.owasp.encoder:encoder`) before the value is passed to `response.getWriter().format()`. This ensures that characters like `<`, `>`, `&`, and quotes are converted to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), preventing the injected content from being interpreted as HTML or script. The import statement `import org.owasp.encoder.Encode;` is added to make the encoder available.

## Behaviour changes

The `format()` method receives an HTML-encoded version of the Referer header as its first argument instead of the raw value. This is the intended behaviour change required to close the XSS vulnerability. The second argument (`obj`) is passed unchanged. No other functionality is altered.
