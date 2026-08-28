## Fix

```java
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

        // Contextual output encoding for an HTML text node (OWASP Java Encoder:
        // org.owasp.encoder:encoder).
        String safeParam = org.owasp.encoder.Encode.forHtml(param);

        // The format string is a constant; untrusted data is only ever an argument.
        response.getWriter().format(java.util.Locale.US, "%s", safeParam);
    }
```

## Explanation

The `Referer` header is attacker-controlled, and it was passed to `Writer.format(...)` as the format string itself, so its characters were both interpreted as format directives and emitted verbatim into a `text/html` response body - allowing an attacker to inject `<script>` or event-handler markup that executes in the victim's browser. The fix inverts the relationship: the format string is now the constant `"%s"` and the untrusted value is supplied as an argument, and that value is HTML-entity encoded with `Encode.forHtml` before it reaches the writer, so `<`, `>`, `&`, and quote characters render as text rather than starting a tag or attribute. Encoding at the sink and matching the encoder to the HTML text context is what removes the weakness; the unused `Object[]` placeholder was dropped because the constant format string consumes exactly one argument, and the `X-XSS-Protection: 0` header was removed since it deliberately disabled a browser-side defence that offered no benefit here.
