## Verdict
exploitable

## Source
Untrusted HTTP Referer header retrieved via `request.getHeaders("Referer")` at line 45

## Fix

**Vulnerable code (line 57):**
```java
response.getWriter().format(param, obj);
```

**Fixed code:**
```java
response.getWriter().print(Encode.forHtml(param));
```

**Required import:**
```java
import org.owasp.encoder.Encode;
```

Ensure OWASP Java Encoder library is present as a dependency.

## Explanation
The Referer header is an untrusted external source that flows through URL decoding without validation into the response body via `format()`. The `format()` call outputs the untrusted data directly to the HTTP response without any HTML encoding, allowing an attacker to inject arbitrary HTML or JavaScript that executes in victims' browsers. The fix replaces the unsafe output with `Encode.forHtml()`, which applies HTML entity encoding (e.g., `<` → `&lt;`, `>` → `&gt;`) to neutralize special characters and ensure the data is rendered as text content rather than executable code. Switching from `format()` to `print()` removes the format-string attack surface as well.

## Behaviour changes
The behavior change is intentional and necessary for security:
- The `format()` method with multiple arguments interpreted the untrusted string as a printf-style format string; `print()` treats it as plain text to output, which is the correct semantics for untrusted data.
- `Encode.forHtml()` converts special characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents, ensuring they are displayed as literal text in the browser rather than interpreted as markup or JavaScript. This is a functional change that prevents code execution but does not affect legitimate rendering of normal text.
- The object array argument `obj` is no longer used; it was only needed by the `format()` method and serves no purpose with `print()`.
