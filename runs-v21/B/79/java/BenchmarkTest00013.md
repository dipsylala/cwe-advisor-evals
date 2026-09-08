## Verdict

Exploitable. The Referer header (untrusted user input) is URL-decoded and then passed directly as a format string to `PrintWriter.format()` on line 57. This creates a format string vulnerability allowing:
1. Attackers to inject format specifiers (%x, %s, %n) to leak or write memory
2. Attackers to inject HTML/script tags that are written to the HTTP response without encoding, resulting in reflected XSS

## Source

**Line 45**: `java.util.Enumeration<String> headers = request.getHeaders("Referer")`

The Referer HTTP header is untrusted user input. At line 48, the first value is extracted: `param = headers.nextElement()`. At line 52, this value is URL-decoded but remains unvalidated: `param = java.net.URLDecoder.decode(param, "UTF-8")`.

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
        // FIXED: Use literal format string and encode param for HTML context to prevent XSS injection
        response.getWriter().format(java.util.Locale.US, "%s", Encode.forHtml(param));
    }
}
```

## Explanation

The vulnerability occurs because untrusted data from the Referer header is used directly as the format string argument in `PrintWriter.format(Locale, String, Object...)`. This allows two attack vectors:

1. **Format String Injection**: An attacker can supply format specifiers (e.g., `%x`, `%s`, `%n`) in the Referer header to read from or write to the application's memory.

2. **Cross-Site Scripting (XSS)**: An attacker can embed HTML or script tags in the Referer header, which are written directly to the HTTP response body without encoding, resulting in code execution in the victim's browser.

The fix applies two changes:
- **Use a literal format string** (`"%s"`) instead of the untrusted `param`, preventing format string injection.
- **Encode the param value** using `org.owasp.encoder.Encode.forHtml()` before output to safely render HTML-special characters (`<`, `>`, `&`, `"`, `'`) as HTML entities, preventing XSS injection.

The OWASP Java Encoder is the recommended context-aware encoding library for Java web applications and is sourced from the `org.owasp.encoder:encoder` artifact (version 1.2.3, already available in the test classpath).

## Behaviour changes

**Change 1**: The `obj` array argument `{"a", "b"}` is no longer passed to `format()`.
- **Reason**: The original code used `param` as a format string with `obj` as varargs arguments. The fixed code uses a literal format string `"%s"` with a single argument (the encoded param), so the unused `obj` array is removed.

**Change 2**: The output now HTML-encodes special characters (`<` becomes `&lt;`, `>` becomes `&gt;`, `&` becomes `&amp;`, `"` becomes `&#34;`, `'` becomes `&#39;`).
- **Reason**: This is the core fix for the XSS vulnerability. Any attacker-supplied content is treated as data and safely rendered as HTML text.

Both changes preserve the core contract of the PrintWriter.format() method: it returns the PrintWriter itself for chaining and writes formatted output to the response body. The encoding ensures that content rendered to the HTTP response body cannot be interpreted as executable code by the browser.

