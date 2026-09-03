## Verdict

Exploitable. The HTTP Referer header is user-controlled and flows directly to the response output sink without proper encoding.

## Source

HTTP Referer header retrieved via `request.getHeaders("Referer")` (line 45), with the first element extracted at line 48. URL decoding at line 52 removes percent-encoding but does not neutralize HTML/JavaScript content.

## Fix

**Vulnerable code (line 57):**
```java
response.getWriter().format(param, obj);
```

**Fixed code:**
```java
response.getWriter().println(Encode.forHtml(param));
```

**Library recommendation:** OWASP Java Encoder library. Add to dependencies (requires import of `org.owasp.encoder.Encode`).

## Explanation

The untrusted Referer header is passed directly to `response.getWriter().format()`, which treats it as a format string and writes it to the response body without encoding. This creates two distinct vulnerabilities: a format string vulnerability via format specifiers like `%x` or `%n` in the header, and a cross-site scripting vulnerability via HTML/JavaScript injection such as `<script>` tags or event handlers. 

The fix replaces the format method with a direct write, removing the format string risk, and applies HTML entity encoding via `Encode.forHtml()` to ensure all HTML special characters (`<`, `>`, `&`, `"`, `'`) are encoded before output. This encoding is context-specific for HTML body content and prevents the browser from interpreting injected markup or script as executable code.

## Behaviour changes

- **Method changed from `format()` to `println()`**: The original code used printf-style formatting with `format(param, obj)`, which is removed. The format method treated `param` as a format string and used `obj` array for argument substitution. The fixed code uses a simple line write with encoding and does not use the `obj` array. The output now includes a trailing newline, which is the standard for HTTP response writing via `println()`.

- **Encoding introduced**: Output is now HTML-encoded, ensuring HTML special characters are converted to entities (e.g., `<` becomes `&lt;`). This is a required security change and does not constitute a regression - legitimate content containing `<`, `&`, and quotes will render correctly as text rather than being interpreted as markup.

- **obj array no longer used**: The original `obj` array parameter is discarded in the fixed version. Since the untrusted parameter should never be used as a format string, there is no valid use for the formatting arguments, and their removal eliminates the format string attack surface.
