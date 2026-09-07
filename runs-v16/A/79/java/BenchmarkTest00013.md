## Verdict

CWE-79 (Cross-site Scripting) confirmed. Untrusted data from the HTTP request header is written directly to the response body without HTML encoding.

## Source

Line 45-48: The Referer header is read into `param` via `request.getHeaders("Referer")`. Headers are untrusted external input.

Line 52: `param` is URL-decoded but not validated or sanitized.

## Fix

Replace line 57:
```java
response.getWriter().format(java.util.Locale.US, param, obj);
```

With:
```java
response.getWriter().print(org.owasp.encoder.Encode.forHtml(param));
```

Require the OWASP Java Encoder library as a dependency.

## Explanation

The vulnerability occurs because `param` (derived from an untrusted HTTP header) is passed directly to the response writer without encoding. An attacker can inject malicious HTML or JavaScript via the Referer header—for example, `<script>alert('XSS')</script>`—which the server will write unencoded into the response body, causing the browser to execute the injected script.

The fix applies context-appropriate output encoding using `Encode.forHtml()`, which converts special HTML characters (`<`, `>`, `&`, `"`, `'`) to HTML entities. This ensures the data is treated as text content, not executable code. Using `Encode.forHtml()` from OWASP Java Encoder is the recommended approach in the project guidance because it handles the complete set of HTML entity escaping and is purpose-built for this context.

The original use of `format()` is also problematic because it treats the first argument as a format string; switching to `print()` avoids potential format string attacks.
