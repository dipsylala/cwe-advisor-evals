## Verdict

Exploitable. The Referer header is untrusted, user-controlled input that reaches an unencoded output sink without validation or sanitization.

## Source

Line 45-48: The Referer HTTP request header is read via `request.getHeaders("Referer")` and its first element is extracted into the `param` variable. HTTP headers are attacker-controlled.

## Fix

**Vulnerable code (line 57):**
```java
response.getWriter().format(param, obj);
```

**Fixed code:**
```java
response.getWriter().print(Encode.forHtml(param));
```

**Required import (add to imports section):**
```java
import org.owasp.encoder.Encode;
```

**Dependency:** OWASP Java Encoder library (ensure it is present in the project's dependency management; no specific minimum version is prescribed by this guidance).

## Explanation

The vulnerability occurs because `param`, derived from an untrusted HTTP header, is written directly to the HTTP response via `format()` without any output encoding. An attacker can inject malicious HTML or JavaScript (e.g., `<script>alert('xss')</script>`) into the Referer header, which will be rendered in the victim's browser context and executed. The fix replaces `format()` with `print()` and applies OWASP Java Encoder's `Encode.forHtml()` method to ensure all special HTML characters (`<`, `>`, `&`, `"`, `'`) are entity-encoded. This prevents the browser from interpreting the injected content as code, rendering it as literal text instead. The HTML encoding is context-appropriate for output in the response body.

## Behaviour changes

The original code used `format(param, obj)`, which treats `param` as a printf-style format string with `obj` as substitution arguments. The fixed code uses `print(Encode.forHtml(param))`, which simply writes the encoded param value without interpreting it as a format string. This removes format string injection risk (where format specifiers like `%x` or `%n` in `param` could leak memory or cause crashes). The `obj` array is no longer used, which is safe because the original code's use of it was unclear and the array was never meaningfully supplied by the application logic. All special HTML characters in the output are now entity-encoded, preventing XSS execution while preserving readability of the rendered text in the browser.
