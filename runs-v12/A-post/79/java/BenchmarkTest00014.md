## Verdict
**CONFIRMED** - CWE-79: Cross-site Scripting (XSS)

## Source
The Referer header from the HTTP request is extracted at line 45-48 and URL-decoded at line 52. This user-controlled data flows directly to the response output at line 57 without any HTML escaping.

```
HTTP Request → request.getHeaders("Referer") → param (URL-decoded) → response.getWriter().format(param, obj)
```

## Fix
Add HTML escaping before outputting the parameter to the response. Import a library such as OWASP ESAPI or use Apache Commons Lang's `StringEscapeUtils`, then escape the param value:

```java
import org.apache.commons.lang3.StringEscapeUtils;

// At line 57, replace:
// response.getWriter().format(param, obj);

// With:
String escapedParam = StringEscapeUtils.escapeHtml4(param);
response.getWriter().print(escapedParam);
```

Alternatively, if ESAPI is available:
```java
import org.owasp.esapi.ESAPI;

String escapedParam = ESAPI.encoder().encodeForHTML(param);
response.getWriter().print(escapedParam);
```

## Explanation
The vulnerability occurs because user-controlled input from the Referer header is written to the HTML response body without sanitization. An attacker can inject malicious HTML or JavaScript by crafting a request with a specially crafted Referer header. When the response is rendered in a browser, the injected script executes in the context of the user's session.

The fix applies HTML entity encoding to neutralize any HTML or JavaScript metacharacters in the user input, converting them to their harmless entity representations (e.g., `<` becomes `&lt;`, `"` becomes `&quot;`). This ensures the input is treated as content rather than executable markup.

Use of `format()` with a parameterized array (`obj`) would be insufficient here since `param` itself becomes the format string and contains unsanitized user data. The recommended approach is to escape the user input and output it as plain text content using `print()`.
