## Verdict

The code is vulnerable to Cross-site Scripting (CWE-79). The `param` variable contains untrusted data from the HTTP Referer header and is written directly to the response body via `response.getWriter().format(param, obj)` without HTML encoding, allowing an attacker to inject malicious scripts.

## Source

Line 57: `response.getWriter().format(param, obj);`

The `param` value originates from the Referer header (line 45-48) and is only URL-decoded (line 52), not HTML-escaped. When passed to `format()`, it is written to the HTTP response body unencoded, enabling XSS.

## Fix

Replace line 57 with HTML-encoded output:

```java
String encoded = org.apache.commons.text.StringEscapeUtils.escapeHtml4(param);
response.getWriter().write(encoded);
```

Alternatively, if using Apache Commons Lang 3.x:

```java
String encoded = org.apache.commons.lang3.StringEscapeUtils.escapeHtml4(param);
response.getWriter().write(encoded);
```

## Explanation

The vulnerability occurs because untrusted HTTP header data flows directly into the response body without HTML encoding. An attacker controlling the Referer header can inject arbitrary HTML/JavaScript. The fix HTML-encodes the parameter before output, converting dangerous characters like `<`, `>`, `&`, and quotes into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, etc.), preventing the browser from interpreting them as markup. This also eliminates the format string risk by using `write()` instead of `format()`, which does not interpret special characters as formatting directives.
