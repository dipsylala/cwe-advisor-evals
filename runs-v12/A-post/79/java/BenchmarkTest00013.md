## Verdict

**Confirmed:** CWE-79 (Cross-site Scripting). User-controlled data from the HTTP Referer header is written directly to the response body without HTML encoding.

## Source

The Referer header value is extracted at line 48:
```java
param = headers.nextElement();
```

This untrusted data flows through a URL decode at line 52 (which does not sanitize) and is passed directly to `response.getWriter().format()` at line 57, where it is written into the response body without encoding.

## Fix

Replace line 57 with HTML-encoded output:

```java
response.getWriter().println(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD.isEmpty() ? 
    "error" : org.owasp.encoder.Encode.forHtml(param));
```

Or using a standard approach:

```java
String encoded = param.replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#x27;");
response.getWriter().println(encoded);
```

Preferably, use OWASP Encoder (org.owasp.encoder.Encode.forHtml()) or Spring Framework's HtmlUtils.htmlEscape() to encode the parameter before writing to the response.

## Explanation

The Referer header is user-controlled data from the HTTP request. The code extracts this value, URL-decodes it, but fails to perform HTML entity encoding before writing it to the response body. An attacker can craft a malicious Referer header containing JavaScript or HTML tags, which will be reflected into the victim's browser and executed in their security context, leading to session hijacking, credential theft, or malware infection.

The fix applies HTML entity encoding to the user input before output, converting dangerous characters (`<`, `>`, `&`, `"`, `'`) to their safe HTML entity equivalents. This prevents the browser from interpreting the payload as code rather than data.
