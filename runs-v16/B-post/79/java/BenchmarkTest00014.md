## Verdict
**EXPLOITABLE** - Untrusted HTTP header data flows to response output without encoding, enabling XSS injection.

## Source
HTTP Referer header via `request.getHeaders("Referer")` at line 45, assigned to `param` at line 48, URL-decoded at line 52.

## Fix
Replace line 57:
```java
// Vulnerable: param from untrusted Referer header written without encoding
response.getWriter().format(param, obj);
```

With:
```java
// Fixed: Encode param for HTML context before output
import org.owasp.encoder.Encode;

response.getWriter().println(Encode.forHtml(param));
```

The import statement should be added at the top of the file with the existing imports:
```java
import org.owasp.encoder.Encode;
```

## Explanation
The vulnerability stems from passing untrusted user input (the HTTP Referer header) directly to `response.getWriter().format()` without encoding. The format method writes the data into the response body, which is rendered as HTML in the client's browser. An attacker can inject malicious HTML tags and JavaScript by controlling the Referer header, which executes in the victim's browser context.

The fix applies context-appropriate output encoding using OWASP Java Encoder's `Encode.forHtml()` method. This method encodes HTML special characters (`<`, `>`, `&`, `"`, `'`) to their entity equivalents, ensuring that any injected markup is rendered as literal text rather than executable code. The encoded value is safe to output in HTML body contexts.

## Behaviour changes
- The Referer header value is now treated as literal text content rather than executable markup
- HTML special characters in the header are converted to entity references (e.g., `<` becomes `&lt;`)
- Malicious script payloads in the Referer header will display as text instead of executing
- Legitimate Referer headers containing ampersands, quotes, or angle brackets will render correctly as escaped text
- The original `format()` call with `obj` parameter is replaced with a simpler `println()` call; if the original intended to use `param` as a format string template with `obj` as replacements, that pattern was incompatible with untrusted input and has been removed
