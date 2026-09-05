## Verdict

Exploitable. The Referer header (attacker-controlled untrusted input) is URL-decoded and written directly into the HTTP response body via `response.getWriter().format()` without any HTML encoding, allowing injection of scripts that execute in the victim's browser.

## Source

Line 45–48: The Referer header is retrieved via `request.getHeaders("Referer")` and extracted as the first element. Referer is attacker-controlled and comes from the HTTP request headers.

## Fix

**Vulnerable code (line 57):**
```java
response.getWriter().format(java.util.Locale.US, param, obj);
```

**Fixed code:**
```java
import org.owasp.encoder.Encode;

// ... in the doPost method, replace line 57 with:
response.getWriter().print(Encode.forHtml(param));
```

## Explanation

The vulnerability occurs because untrusted input from the Referer header is used as a format string argument to `response.getWriter().format()`, which outputs it directly to the HTML response without encoding. This allows an attacker to inject arbitrary HTML and JavaScript that will execute in the victim's browser.

The fix applies OWASP Java Encoder's `Encode.forHtml()` method at the output sink, which converts dangerous characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents, ensuring the attacker-supplied content is treated as text data rather than executable code. The `format()` call is replaced with a simpler `print()` call, eliminating the secondary risk of format string injection through the first argument to `format()`.

## Behaviour changes

- **HTML encoding applied**: Characters like `<`, `>`, `&`, `"`, and `'` in the Referer header are converted to HTML entities, preventing script injection. Legitimate content containing these characters will still display correctly as text.
- **Format string processing removed**: The `format()` method and its `obj` array argument are no longer used, simplifying the code and eliminating format string injection risk. The output is written as a literal string.
- **Library dependency added**: OWASP Java Encoder (org.owasp.encoder:owasp-encoder) must be present on the classpath. No minimum version is specified in the guidance; confirm the resolved version against SCA tooling before merging.
