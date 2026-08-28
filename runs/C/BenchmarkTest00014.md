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
    response.getWriter().format("%s", Encode.forHtml(param));
}
```

## Explanation

The URL-decoded `Referer` header was handed to `response.getWriter().format(...)` as the format string, letting an attacker control the exact bytes written into the `text/html` response body and have their content parsed as markup by the victim's browser. The fix pins the format string to the literal `"%s"` and moves the untrusted value into the argument position, then passes it through `Encode.forHtml()` from the OWASP Java Encoder, which converts `<`, `>`, `"`, `'`, and `&` to HTML entities appropriate for the HTML body context established by the `text/html;charset=UTF-8` content type. Encoding at the sink is what removes the weakness: the header value can no longer terminate a tag or open a `<script>`/`<svg onload=>` element, so it renders as visible text instead of executing, and encoded or case-varied payloads that defeat pattern blocklists are neutralised by the same transformation. The now-unreferenced `Object[] obj` was removed, the `X-XSS-Protection: 0` header that turned off the browser's legacy filter was dropped, and a strict `Content-Security-Policy` header was added purely as a secondary containment layer.
