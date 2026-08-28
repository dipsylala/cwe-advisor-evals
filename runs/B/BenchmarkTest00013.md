## Fix

```java
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

        // Defence in depth: restrict script execution sources.
        response.setHeader("Content-Security-Policy", "default-src 'self'");

        // The header value is data, never a format string, and is HTML-entity encoded
        // for the HTML body context before it reaches the writer.
        response.getWriter().format(java.util.Locale.US, "%s", Encode.forHtml(param));
    }
}
```

## Explanation

The `Referer` header value was being passed as the *format string* argument to `PrintWriter.format`, so every character of an attacker-controlled header was copied verbatim into a `text/html` response body, letting a payload such as `<svg onload=alert(1)>` execute in the victim's browser. The fix pins the format string to the literal `"%s"` and moves the untrusted value into the argument position, then encodes it with `Encode.forHtml()` from the OWASP Java Encoder so that `<`, `>`, `&`, and quotes are emitted as HTML entities and the data can never be parsed as markup or script in the HTML body context where it lands. The now-unused `Object[] obj` placeholder was dropped because a literal single-argument format consumes it no longer, and `X-XSS-Protection: 0` — which explicitly turned off the browser's own auditor — was replaced with a `default-src 'self'` Content-Security-Policy header as a secondary layer behind the encoding rather than in place of it. Confining the untrusted value to an argument also removes the companion format-string exposure, where conversions like `%n` or a wide `%s` width in the header could disrupt or inflate the response.
