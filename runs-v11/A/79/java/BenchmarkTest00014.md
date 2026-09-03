## Verdict
Confirmed. The request header value is written directly to the response body without HTML encoding, allowing XSS injection.

## Source
Line 57: `response.getWriter().format(param, obj);`

The `param` variable contains untrusted data from the HTTP request header "Referer" (line 45-48), URL-decoded (line 52), and written directly to the response body without any HTML entity encoding (line 57).

## Fix
Replace line 57 with HTML-encoded output:

```java
String encodedParam = param.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#x27;");
response.getWriter().write(encodedParam);
```

Alternatively, using `format()` with safe formatting:

```java
String encodedParam = param.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
response.getWriter().format("%s", encodedParam);
```

## Explanation
The vulnerability occurs because `param` is passed directly to `format()` without encoding. An attacker can inject malicious HTML or JavaScript through the Referer header, which will then be written unescaped into the response body, executing in the victim's browser.

The fix applies HTML entity encoding to replace dangerous characters (`&`, `<`, `>`, `"`, `'`) with their safe entity equivalents before writing to the response. This ensures that any user-controlled content is treated as data, not as HTML markup or script code, preventing XSS execution while preserving the original data in readable form.
