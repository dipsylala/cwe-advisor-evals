## Verdict

CONFIRMED - CWE-79 Cross-Site Scripting. The Referer header (untrusted source) is decoded but not HTML-encoded before being written to the HTTP response body via `response.getWriter().format()`.

## Source

**Input source**: Line 45 - `request.getHeaders("Referer")`

The Referer header value is attacker-controlled and treated as untrusted data.

**Data flow**:
- Line 45: Referer header retrieved via `getHeaders()`
- Line 48: First element assigned to `param` variable
- Line 52: URL-decoded via `URLDecoder.decode(param, "UTF-8")` (no sanitization, only decoding)
- Line 57: Written directly to response body via `response.getWriter().format(java.util.Locale.US, param, obj)`

## Fix

Add the OWASP Java Encoder library to handle context-aware output encoding:

**Maven dependency** (if not already present):
```xml
<dependency>
    <groupId>org.owasp.encoder</groupId>
    <artifactId>encoder</artifactId>
    <version>1.2.3</version>
</dependency>
```

**Fixed code**:

```java
import org.owasp.encoder.Encode;

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
    // HTML-encode the untrusted parameter before writing to response
    response.getWriter().format(java.util.Locale.US, Encode.forHtml(param), obj);
}
```

## Explanation

The vulnerability occurs because untrusted input from the HTTP Referer header is written directly to the response body without HTML encoding. An attacker can inject malicious HTML or JavaScript (e.g., `<script>alert('xss')</script>`) into the Referer header, which will be rendered and executed by the victim's browser.

The fix applies `Encode.forHtml()` from the OWASP Java Encoder library at the output sink (line 57). This method HTML-encodes special characters (`<`, `>`, `&`, `"`, `'`) so that any injected markup is rendered as literal text rather than executed as code. The encoding preserves the format string's structure—the remaining format arguments (`obj`) are still processed normally by the `format()` method—while preventing the untrusted Referer value from being interpreted as executable content.

Note: The `response.setHeader("X-XSS-Protection", "0")` directive disables browser XSS protections; this should be removed in a hardened configuration, but output encoding is the primary defence and will prevent the vulnerability regardless.

## Behaviour changes

- **Output encoding**: The Referer header value is now HTML-encoded before writing to the response. Any HTML special characters will appear as entities (e.g., `<` becomes `&lt;`) rather than being interpreted as markup.
- **Legitimate content**: Referer values containing characters like `<`, `>`, `&`, quotes will render correctly as visible text (escaped) rather than being treated as code.
- **Format string semantics preserved**: The `format()` method still processes format specifiers and arguments from `obj` normally; only the untrusted `param` value is encoded.
