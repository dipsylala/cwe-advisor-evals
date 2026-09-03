## Verdict

Exploitable

## Source

The HTTP Referer header (line 45) from `request.getHeaders("Referer")` is completely attacker-controlled and untrusted. The value is extracted on line 48 and URL-decoded on line 52, but no output encoding is applied before rendering.

## Fix

**Vulnerable code (line 57):**
```java
response.getWriter().format(java.util.Locale.US, param, obj);
```

**Fixed code:**
```java
response.getWriter().println(org.owasp.encoder.Encode.forHtml(param));
```

**Library recommendation:** OWASP Java Encoder (`org.owasp.encoder:encoder`) — version to be confirmed via dependency management tool; ensure it is present on the classpath. Add to Maven `pom.xml` or Gradle `build.gradle` if not already included.

## Explanation

The vulnerability occurs because untrusted data from the HTTP Referer header is written directly to the response body via `response.getWriter().format()` without any output encoding. An attacker can inject malicious JavaScript in the Referer header — for example, `<script>alert(1)</script>` — which will execute in the victim's browser. The fix applies context-aware HTML entity encoding using `Encode.forHtml()` to neutralize HTML special characters (`<`, `>`, `&`, `"`, `'`). This converts them to entity references (`&lt;`, `&gt;`, etc.) so they are treated as data, not executable markup. The `format()` call is replaced with `println()` since the untrusted Referer header should not be used as a format string with additional arguments.

## Behaviour changes

- The `format()` method call with locale and object array is replaced with a simple `println()`. The original code treated untrusted header data as a format string, which is incorrect; the format specifiers and object array are removed to prevent format string abuse.
- Output is now HTML-encoded: special characters in the Referer header will be displayed as HTML entities rather than raw text, preventing script injection at the cost of changing how those characters are displayed (e.g., `<` becomes `&lt;`). This is the intended and necessary behaviour change to close the XSS vulnerability.
