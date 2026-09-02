## Verdict

Confirmed. The `Referer` request header is decoded and then written into the HTTP response body without HTML-encoding, and it is additionally used as the *format string* itself for `Formatter.format()` rather than as an argument — both paths let an attacker-controlled value reach the response body unescaped, producing reflected Cross-Site Scripting.

## Source

`BenchmarkTest00013.java`, line 45-48: `request.getHeaders("Referer")` is read, and the first element is assigned to `param`. Line 52 URL-decodes it: `param = java.net.URLDecoder.decode(param, "UTF-8");`. This is fully attacker-controlled — a client can set an arbitrary `Referer` header on the request.

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

    response.setHeader("X-XSS-Protection", "0");
    Object[] obj = {"a", "b"};
    String safeParam = org.owasp.encoder.Encode.forHtml(param);
    // Fixed format string; user data is passed as a substitution argument, never as the format string itself.
    response.getWriter().format(java.util.Locale.US, "%s %s %s", safeParam, obj[0], obj[1]);
}
```

Add the OWASP Encoder dependency (`org.owasp.encoder:encoder`) if it is not already on the classpath.

## Explanation

Two separate problems combine here. First, `param` (the decoded `Referer` value) is passed as the *format string* argument to `Formatter.format(Locale, String, Object...)` rather than as data — an attacker who controls the format string can inject arbitrary literal text (including `<script>` markup) directly into the output, and format specifiers in the input are not a defense here since any literal characters in the format string pass through verbatim to the writer. Second, even once `param` is moved to its correct position as a *substitution argument* under a fixed, hardcoded format string (`"%s %s %s"`), `%s` does not perform any output encoding — it just calls `toString()` and writes the raw characters, so an attacker-controlled value containing `<`, `>`, `"`, or `'` still reaches the browser as live HTML/script content.

The fix addresses both: it hardcodes the format string so request data can never control formatting behavior, and it HTML-encodes `param` with `Encode.forHtml()` before it is substituted into the response, so any HTML-significant characters are rendered as inert text rather than parsed as markup. Encoding at the point of output (rather than trying to sanitize or blocklist characters on input) ensures the value is safe regardless of what characters it contains, and setting `X-XSS-Protection: 0` (already present) does not provide any protection here, so encoding is the only control preventing exploitation.
