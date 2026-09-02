## Verdict

Confirmed. Untrusted data from the HTTP Referer header is written directly to the response body without HTML encoding.

## Source

HTTP request header `Referer` (line 45), obtained via `request.getHeaders("Referer")`. URL decoded at line 52 and stored in variable `param` without encoding.

## Fix

Replace line 57 with HTML-encoded output:

```java
// Add import at the top of the file:
import org.owasp.encoder.Encode;

// Replace the vulnerable line:
response.getWriter().println(Encode.forHtml(param));
```

**Vulnerable code:**
```java
response.getWriter().format(java.util.Locale.US, param, obj);
```

**Fixed code:**
```java
response.getWriter().println(Encode.forHtml(param));
```

## Explanation

The original code passes user-controlled input (`param`) directly to `PrintWriter.format()` without encoding, which writes it unescaped into the HTML response body. An attacker can craft a malicious Referer header containing JavaScript (e.g., `<script>alert('XSS')</script>` or event handlers like `"><img src=x onerror=alert(1)>`) that executes in the victim's browser.

The fix applies HTML entity encoding using OWASP Java Encoder's `Encode.forHtml()` before writing to the response. This method escapes characters that have meaning in HTML context (`<`, `>`, `&`, `'`, `"`) into harmless entity references, rendering the payload inert while preserving readability of legitimate header values.

## Behaviour changes

- **Output encoding**: Untrusted data is now HTML-escaped before rendering. Characters like `<`, `>`, `&` are converted to `&lt;`, `&gt;`, `&amp;` respectively.
- **Format string removed**: The unsafe use of `format()` with untrusted input as the format string is eliminated; output is now plain text encoding rather than formatted output.
- **Removed unused array**: The `Object[] obj = {"a", "b"}` array at line 55 is no longer used by the output statement and can be deleted to clean up unused code.
