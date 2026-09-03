## Verdict

The finding is confirmed. Line 30 outputs an unsanitized user-supplied parameter directly into HTML content without escaping, allowing arbitrary HTML and JavaScript injection.

## Source

The vulnerability originates at line 24 where `displayName` is retrieved from the HTTP request parameter without validation:

```java
String displayName = request.getParameter("displayName");
```

The displayName is then rendered directly into the HTML response at line 30 via JSP expression syntax without any escaping:

```jsp
<p>Welcome, <%= displayName %>!</p>
```

An attacker can inject malicious HTML or JavaScript by supplying a crafted `displayName` parameter, such as `?displayName=<script>alert('XSS')</script>` or `?displayName=<img src=x onerror=alert('XSS')>`.

## Fix

Replace the vulnerable line 30 with HTML-escaped output using JSP Standard Tag Library (JSTL) `fn:escapeXml()` function:

```jsp
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
```

Then modify line 30 to:

```jsp
<p>Welcome, ${fn:escapeXml(displayName)}!</p>
```

Alternatively, if using Expression Language 3.0+, use the built-in escaping:

```jsp
<p>Welcome, <c:out value="${displayName}" escapeXml="true" />!</p>
```

Or continue using scriptlets with explicit escaping:

```jsp
<p>Welcome, <%= org.apache.commons.lang3.StringEscapeUtils.escapeHtml4(displayName) %>!</p>
```

## Explanation

The original code passes user input directly to an HTML context without escaping special characters. HTML metacharacters like `<`, `>`, `&`, `"`, and `'` have special meaning in HTML and must be escaped to prevent them from being interpreted as HTML syntax.

HTML escaping converts these characters to their entity equivalents: `<` becomes `&lt;`, `>` becomes `&gt;`, `&` becomes `&amp;`, etc. This forces the browser to render them as literal text rather than HTML markup or attributes, preventing script injection.

JSTL's `fn:escapeXml()` is the recommended approach in modern JSP because it is concise, readable, and performs proper HTML entity encoding. If JSTL is unavailable, `c:out` with `escapeXml="true"` provides the same protection within JSP's Expression Language, or Apache Commons Lang's `StringEscapeUtils.escapeHtml4()` can be used for scriptlet-based output.
