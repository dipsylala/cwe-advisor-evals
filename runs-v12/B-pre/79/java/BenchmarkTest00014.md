## Verdict

**Confirmed exploitable**: Untrusted HTTP Referer header is written to the response body without HTML encoding at line 57, allowing XSS.

## Source

The Referer header, obtained from `request.getHeaders("Referer")` at line 45, is untrusted attacker-controlled input. URL decoding at line 52 does not neutralize HTML/JavaScript metacharacters, leaving the value unsafe for rendering in HTML context.

## Fix

Add import:
```java
import org.owasp.encoder.Encode;
```

Replace line 57:
```java
// Vulnerable code (before)
response.getWriter().format(param, obj);

// Fixed code (after)
response.getWriter().println(Encode.forHtml(param));
```

Or using `write()` instead of `println()`:
```java
response.getWriter().write(Encode.forHtml(param));
```

## Explanation

The vulnerability occurs because untrusted HTTP header data is rendered into the response body without output encoding. The Referer header is attacker-controlled; an attacker can inject HTML markup or JavaScript code that will execute in the victim's browser.

The fix applies context-appropriate output encoding using OWASP Java Encoder's `Encode.forHtml()` method, which encodes special characters (`<`, `>`, `&`, `'`, `"`) to their HTML entity equivalents. This ensures that any markup or script tags in the untrusted input are rendered as literal text rather than executed as code.

Note: The original code also uses `format()` with untrusted data as a format string, which is a format-string vulnerability risk. Replacing with `println()` or `write()` eliminates both the format-string and XSS vectors.

## Behaviour changes

- The response now safely displays the Referer header value as escaped HTML text.
- Legitimate Referer header values containing `<`, `>`, or `&` are preserved (as entity-encoded text) rather than being truncated or causing parser errors.
- Malicious payloads in the Referer header (e.g., `<script>alert(1)</script>`) are rendered as escaped text instead of executing.
- The unsafe `format()` call is replaced with `println()`, preventing format-string exploitation and simplifying the output.
