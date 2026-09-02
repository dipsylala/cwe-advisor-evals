## Verdict

Exploitable. Untrusted HTTP header (Referer) flows directly to the HTTP response body without encoding.

## Source

Line 45-48: `request.getHeaders("Referer")` retrieves an untrusted HTTP header from the client. The first value is extracted and assigned to `param`:
```java
java.util.Enumeration<String> headers = request.getHeaders("Referer");
if (headers != null && headers.hasMoreElements()) {
    param = headers.nextElement();
}
```

Line 52 URL-decodes the value but does not validate or encode it for output context:
```java
param = java.net.URLDecoder.decode(param, "UTF-8");
```

## Fix

**Vulnerable code (line 57):**
```java
response.getWriter().format(param, obj);
```

**Fixed code:**
```java
import org.owasp.encoder.Encode;

// ... in doPost method:
response.getWriter().println(Encode.forHtml(param));
```

Alternatively, if `format()` was intentional for string formatting:
```java
import org.owasp.encoder.Encode;

response.getWriter().format(Encode.forHtml(param));
```

The first approach is preferred because the original use of `format(param, obj)` treats `param` as an untrusted format string, which introduces both XSS and format-string injection risks.

## Explanation

The Referer header value is attacker-controlled and reaches `response.getWriter().format()` without any HTML encoding. By supplying `<script>alert(1)</script>` or similar in the Referer header, an attacker can inject JavaScript that executes in the victim's browser when the response is rendered. `Encode.forHtml()` converts dangerous characters (`<`, `>`, `&`, `"`, `'`) to HTML entities (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), neutralizing the injection while preserving the original data as displayable content. The fix applies OWASP Java Encoder at the output sink, enforcing context-aware encoding appropriate for HTML body text.

## Behaviour changes

The fixed code calls `println()` without a format string, whereas the original calls `format(param, obj)`. The original passed the Object array `obj` to format, which would have been referenced if `param` contained format specifiers like `%s`. The fixed code discards the `obj` array and writes only the encoded header value, eliminating both the format string vulnerability and the undefined use of `obj`. If the intent was to interpolate `obj` values into the output, the caller must be updated to supply a safe, application-controlled format string with `Encode.forHtml()` encoding applied to each user-supplied value before passing them as format arguments.
