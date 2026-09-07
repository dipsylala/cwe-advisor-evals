## Verdict
Exploitable

## Source
`request.getHeaders("Referer")` at line 45, which extracts the HTTP Referer header—untrusted user-controlled data.

## Fix

**Vulnerable code (line 57):**
```java
response.getWriter().format(java.util.Locale.US, param, obj);
```

**Fixed code (line 57):**
```java
response.getWriter().print(Encode.forHtml(param));
```

**Required import (add after existing imports):**
```java
import org.owasp.encoder.Encode;
```

**Required dependency:**
Add OWASP Java Encoder library to the project's build configuration (e.g., `pom.xml` or `build.gradle`). The guidance does not specify a version, so confirm the version against the OWASP Encoder project and your SCA tooling before merging.

## Explanation
The Referer header is untrusted user input that flows through URL decoding but is never encoded before being written to the response body. The original code uses `format()` with `param` as the format string, which creates two vulnerabilities: CWE-79 XSS (special characters like `<` and `>` are injected as-is) and CWE-134 format string (format specifiers in the header are interpreted). The fix uses OWASP Java Encoder's `Encode.forHtml()` method to HTML-encode the parameter before writing it, converting dangerous characters (`<`, `>`, `&`, `"`, `'`) to their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This ensures the data is rendered as text content in the HTML body, not as markup or script code.

## Behaviour changes
- **format() → print()**: The original code treated `param` as a format string (CWE-134 violation). The fix treats it as literal data by using `print()` instead, which is the correct pattern for rendering user-supplied content.
- **HTML encoding applied**: Special characters are escaped to entities. For example, `<script>alert(1)</script>` becomes `&lt;script&gt;alert(1)&lt;/script&gt;`, which renders as visible text rather than executing as code.
- **obj array removed**: The original `Object[] obj = {"a", "b"}` array was used only as format arguments and is no longer needed since `print()` does not interpret format specifiers.
- **Import added**: `org.owasp.encoder.Encode` imported to support the encoding call.
