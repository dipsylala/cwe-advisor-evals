## Verdict
The code is vulnerable to Cross-Site Scripting (CWE-79). The Referer header value is written directly to the HTTP response body without HTML encoding.

## Source
Line 57 writes user-controlled data from the Referer header directly into the response:
```java
response.getWriter().format(param, obj);
```

The data flows from `request.getHeaders("Referer")` (line 45) through URL decoding (line 52) to this output sink. The `format()` method interprets and writes the string directly to the response body without escaping HTML metacharacters.

## Fix
Replace the vulnerable format call with HTML-encoded output. Use an encoding library to escape the parameter before writing:

```java
import org.apache.commons.text.StringEscapeUtils;

// In the doPost method:
response.getWriter().write(StringEscapeUtils.escapeHtml4(param));
```

Alternatively, if using OWASP ESAPI:
```java
import org.owasp.esapi.ESAPI;

response.getWriter().write(ESAPI.encoder().encodeForHTML(param));
```

## Explanation
The vulnerability occurs because the Referer header (attacker-controlled) is written directly to the HTTP response without encoding. An attacker can inject JavaScript by setting the Referer to `<script>alert('XSS')</script>`, which executes in the victim's browser context.

The `format()` method is a format string sink that writes its output directly to the response stream. Using `response.getWriter().format(userInput, ...)` where userInput is untrusted data creates an XSS vulnerability.

The fix applies HTML entity encoding (escaping `<`, `>`, `&`, `"`, `'`) so that HTML/JavaScript metacharacters are rendered as text rather than interpreted by the browser. This breaks the injection chain while preserving the legitimate content for display.
