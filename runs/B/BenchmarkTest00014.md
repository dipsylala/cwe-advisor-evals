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

        // Defence in depth: restrict script execution sources.
        response.setHeader("Content-Security-Policy", "default-src 'self'");

        // The header value is data, never a format string, and is HTML-entity encoded
        // for the HTML body context before it reaches the writer.
        response.getWriter().format("%s", Encode.forHtml(param));
    }
}
```

## Explanation

The URL-decoded `Referer` header flowed straight into `PrintWriter.format` as the format string, so an attacker-supplied value was written character-for-character into a `text/html` response and any markup it carried — `<script>`, `<img onerror=…>`, an attribute breakout — was parsed and executed by the victim's browser. The remediation makes the format string a constant `"%s"` and passes the header value as a data argument wrapped in `Encode.forHtml()` from the OWASP Java Encoder, which entity-encodes the HTML-significant characters at the sink for the HTML body context in which the value is rendered, so the value can only ever display as text. The leftover `Object[] obj` was removed once the literal format takes a single argument, and the `X-XSS-Protection: 0` header, which disabled a browser-side mitigation, gave way to a `default-src 'self'` Content-Security-Policy that backstops the encoding instead of substituting for it. Treating the header as an argument rather than a format also closes the parallel format-string hazard, since conversions embedded in the header are no longer interpreted by the formatter.
