## Verdict

Exploitable. Confidence: high.

## Source

`HttpServletRequest.getHeaders("Referer")` (line 45) - the first `Referer` header value, attacker-controlled on the wire. It is URL-decoded at line 52 (`java.net.URLDecoder.decode(param, "UTF-8")`), which does not neutralize HTML metacharacters and can even reveal characters that were percent-encoded in the raw header. The decoded value flows unmodified into `param` and reaches the sink with no encoding or validation in between.

## Fix

Vulnerable code (line 57):

```java
response.setHeader("X-XSS-Protection", "0");
Object[] obj = {"a", "b"};
// SAST FINDING: CWE-79 - attacker-controlled Referer header written into the response body unencoded
response.getWriter().format(param, obj);
```

Fixed code:

```java
import org.owasp.encoder.Encode;
// ...
response.setHeader("X-XSS-Protection", "0");
Object[] obj = {"a", "b"};
response.getWriter().format(Encode.forHtml(param), obj);
```

Library recommendation: OWASP Java Encoder (`org.owasp.encoder:encoder`). The knowledge base entry gives no minimum safe version for this library - confirm the resolved version against SCA/dependency-check tooling before merging; do not add a version from memory.

## Explanation

The response is `text/html`, and `param` (the reflected `Referer` header) is written straight into the response body as the pattern argument to `PrintWriter.format()` with no output encoding, so any HTML or script markup in the header is rendered verbatim by the browser. Wrapping `param` in `Encode.forHtml()` converts `<`, `>`, `&`, `"`, `'` and other HTML-significant characters to their entity equivalents before the value reaches the sink, so injected markup is displayed as inert text instead of being parsed as HTML. This is the correct context because the value lands directly in the HTML body with no surrounding attribute, script, or URL context to account for.

## Behaviour changes

None to the sink's observable contract: the call is still `PrintWriter.format(String, Object...)`, still writes to the same response writer, still passes the same `obj` array, and the return value (the `PrintWriter`, for chaining) is unused before and after. The only change is that HTML-significant characters in the reflected `Referer` value are now rendered as their literal text (e.g. `&lt;script&gt;` instead of `<script>`) rather than as markup - this is the intended effect of closing the weakness, not a side effect. One pre-existing behavior is unchanged by this fix and worth noting: `param` is still used as the *format pattern* (not a format argument), so a `Referer` value containing a stray `%` followed by a non-conversion character can still throw `java.util.UnknownFormatConversionException` at this line, same as in the original code - this fix does not introduce or remove that condition.
