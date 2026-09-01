## Verdict

Exploitable. Untrusted data from the HTTP Referer header is written directly to the response body via `response.getWriter().format()` without HTML encoding, allowing an attacker to inject arbitrary HTML and JavaScript that executes in victims' browsers.

## Source

The untrusted Referer header is obtained via `request.getHeaders("Referer")` at line 45, extracted as the first element at line 48, URL-decoded at line 52, and passed directly to the response output sink at line 57 without encoding.

## Fix

**Vulnerable code (line 57):**
```java
response.getWriter().format(java.util.Locale.US, param, obj);
```

**Fixed code:**
```java
response.getWriter().format(java.util.Locale.US, org.owasp.encoder.Encode.forHtml(param), obj);
```

This requires the OWASP Java Encoder library on the classpath (dependency: `org.owasp.encoder:encoder`). Apply context-appropriate HTML encoding at the output sink using `Encode.forHtml()`, which escapes characters that have special meaning in HTML (`<`, `>`, `&`, `"`, `'`) to their entity equivalents, preventing script injection while preserving the semantic meaning of legitimate content.

## Explanation

The Referer header is user-controlled and flows from line 45 through line 52 (URL decoding does not provide HTML safety) directly to the `response.getWriter().format()` sink at line 57. The `format()` method writes its arguments to the HTTP response body without escaping, so any HTML or JavaScript in the `param` value executes in the victim's browser. The fix applies `org.owasp.encoder.Encode.forHtml()` at the sink, encoding the untrusted value for safe inclusion in HTML body text. This transforms dangerous characters into HTML entities that render as text rather than executable code, closing the injection vector while maintaining correct display of legitimate content.

## Behaviour changes

The `format()` call's format string argument is now the HTML-encoded version of `param`. Characters in the original `param` value that have special meaning in HTML (`<`, `>`, `&`, `"`, `'`) will be replaced with their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`) in the output. This is the required security fix and does not alter the contract of `format()` — it still writes to the response body; it only ensures the output is safe for HTML rendering rather than executable.
