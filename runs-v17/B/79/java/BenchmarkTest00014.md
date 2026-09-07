## Verdict

FIXED

## Source

Untrusted data source: HTTP `Referer` header read via `request.getHeaders("Referer")` at lines 45–49, URL-decoded at line 52, assigned to `param`.

Data flow: `param` is passed directly to `response.getWriter().format(param, obj)` at line 57 without any HTML encoding.

Sink: `PrintWriter.format()` at line 57 writes the untrusted value to the HTTP response body without encoding, allowing XSS injection.

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
        // SAST FINDING: CWE-79 (Cross-site Scripting) - request data is written into the HTTP response body. Sink is the next statement.
        response.getWriter().print(Encode.forHtml(param));
    }
}
```

## Explanation

The vulnerability occurs because `param`, sourced from the untrusted HTTP `Referer` header, is passed directly to `PrintWriter.format()` as the format string argument. This writes the value to the response body without any HTML encoding, allowing an attacker to inject arbitrary HTML and JavaScript that executes in the victim's browser.

The fix applies OWASP Java Encoder's `Encode.forHtml()` method, which HTML-encodes the untrusted value before writing it to the response. This converts dangerous characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), preventing interpretation as HTML or script markup. The encoding is applied at the output sink (the `PrintWriter`) in the HTML body context, matching the guidance requirement for context-specific encoding.

The import `org.owasp.encoder.Encode` is added to make the encoder API available. The now-unused `Object[] obj` variable is removed, as the fix changed the sink call from `format(param, obj)` to `print(Encode.forHtml(param))`, eliminating the need for format arguments.

## Behaviour changes

**Output format change:** The original code used `response.getWriter().format(param, obj)` which treated `param` as a format string (e.g., if `param` contained `%s`, it would be replaced with elements from the `obj` array). The fixed code uses `print(Encode.forHtml(param))`, which writes the encoded value literally without format string processing. 

Example:
- Original: if `param = "Value: %s"`, output would be `"Value: a"` (using `obj[0]`)
- Fixed: if `param = "Value: %s"`, output would be `"Value: %s"` (literal)

This change is necessary to prevent both XSS injection and format string injection. Any application logic that depends on format specifiers in the `Referer` header will observe different output, but such logic is inherently unsafe and should not exist in production code.
