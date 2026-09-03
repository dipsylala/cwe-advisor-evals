## Verdict
CWE-79 confirmed. User-controlled input from the Referer header is output to the HTTP response without HTML escaping.

## Source
Line 57: `response.getWriter().format(java.util.Locale.US, param, obj);`

The `param` variable contains the value of the Referer header (line 48), which is URL-decoded (line 52) and then passed directly to the response output. The format() method writes this unsanitized value into the HTML response body.

## Fix
Replace line 57 with:
```java
response.getWriter().format(java.util.Locale.US, "%s", org.owasp.encoder.Encode.forHtml(param));
```

This fix requires adding the OWASP Encoder dependency (org.owasp.encoder:owasp-java-encoder) to the project.

Alternative without external dependencies:
```java
response.getWriter().format(java.util.Locale.US, "%s", param.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#x27;"));
```

## Explanation
The vulnerability exists because user-controlled header values are written directly to the HTTP response without HTML encoding. An attacker can inject JavaScript or HTML by crafting a malicious Referer header, which will execute in the victim's browser.

The fix separates the format string from the user input: a literal "%s" format string is provided, and the user input is passed as an argument. The OWASP Encoder library's `forHtml()` method HTML-escapes the input, converting dangerous characters like `<`, `>`, `&`, and quotes to their safe HTML entity equivalents. This prevents any injected scripts or HTML tags from being interpreted by the browser.
