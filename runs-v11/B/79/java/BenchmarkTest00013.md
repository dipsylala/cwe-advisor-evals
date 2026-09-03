## Verdict

Exploitable. Untrusted HTTP header data flows directly to the response output sink without any HTML encoding.

## Source

Line 45: `java.util.Enumeration<String> headers = request.getHeaders("Referer");`

The Referer HTTP header is user-controlled and retrieved without validation. Line 48 extracts the first header value into `param`. Line 52 applies URL decoding, which is a transformation but not XSS encoding. The untrusted `param` then flows directly to the response sink.

## Fix

Vulnerable code (line 57):
```java
response.getWriter().format(java.util.Locale.US, param, obj);
```

Fixed code (line 57 and import):
```java
import org.owasp.encoder.Encode;

// In doPost method:
response.getWriter().print(Encode.forHtml(param));
```

## Explanation

The original code writes untrusted input from the HTTP request header directly to the response body via `PrintWriter.format()` without any encoding. An attacker can craft a Referer header containing JavaScript payloads (e.g., `<script>alert(1)</script>` or event handlers) which will execute in the victim's browser context. The fix applies context-specific output encoding using OWASP Java Encoder's `Encode.forHtml()` method, which escapes HTML special characters (`<`, `>`, `&`, `"`, `'`) to prevent script injection. The `format()` call is replaced with `print()` since `param` is user data, not a format string template.

## Behaviour changes

The `format()` call is replaced with `print()`: The original code misused `format()` by passing untrusted data as a format string. The fixed code uses `print()` to output the encoded string directly.

HTML special characters in the Referer header (`<`, `>`, `&`, `"`, `'`) will now be entity-encoded in the response (e.g., `<` becomes `&lt;`). This prevents the characters from being interpreted as HTML markup or JavaScript syntax while preserving the readability of the actual header value for legitimate uses.

OWASP Java Encoder dependency must be present on the classpath. Confirm the version via SCA or dependency-check tooling before merging.
