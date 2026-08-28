## Fix

```java
// Add to the imports at the top of the file:
// import org.owasp.encoder.Encode;

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

    // Defence-in-depth backstop; the encoding below is the actual fix.
    response.setHeader("Content-Security-Policy", "default-src 'self'");

    // The untrusted header is passed as a format ARGUMENT, never as the format string,
    // and is HTML-entity encoded for the HTML body context it is rendered into.
    response.getWriter().format(java.util.Locale.US, "%s", Encode.forHtml(param));
}
```

## Explanation

The `Referer` header value flowed, after URL decoding, straight into `response.getWriter().format(...)` as the format string itself, so the attacker controlled both the literal text emitted into the `text/html` response body and the format directives applied to it. The corrected code makes the format string a fixed literal (`"%s"`) and demotes the untrusted value to an argument, then wraps it in `Encode.forHtml()` from the OWASP Java Encoder so that `<`, `>`, `"`, `'`, and `&` are emitted as HTML entities. Because the response is declared `text/html`, the HTML body is the correct encoding context; the payload is therefore rendered as inert text rather than parsed as markup, closing the injection regardless of the vector used (`<script>`, `<svg onload=>`, attribute breakout, or an encoded variant that a blocklist would miss). The unused `Object[] obj` placeholder was dropped since nothing consumes it once the format string is a fixed literal, the `X-XSS-Protection: 0` header that explicitly disabled the browser's legacy filter was removed, and a strict `Content-Security-Policy` was added as a secondary layer — it is a backstop, not the remediation.
