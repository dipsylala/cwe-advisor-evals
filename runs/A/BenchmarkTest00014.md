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
        response.getWriter().format("%s", safeParam);
    }
```

## Explanation

The `Referer` header is attacker-controlled and was handed to `Writer.format(...)` as the format string, so its content was written straight into a `text/html` response body where a browser parses it as markup - an attacker who controls that header controls script executing in the victim's page. The corrected code passes a constant `"%s"` format string and moves the untrusted value into the argument position, and encodes it with `Encode.forHtml` so that `<`, `>`, `&`, `"`, and `'` become HTML entities and can no longer open a tag or break out of an attribute. Encoding immediately before the sink, in the encoder that matches the HTML text context the data lands in, is what closes the cross-site scripting path; the unused `Object[]` placeholder is no longer needed with a single-directive format string, and the `X-XSS-Protection: 0` header was removed because it explicitly turned off a browser protection while providing nothing in return.
