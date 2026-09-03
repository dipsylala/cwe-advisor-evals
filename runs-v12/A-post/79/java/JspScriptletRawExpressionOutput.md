## Verdict

This is a confirmed Cross-site Scripting (XSS) vulnerability. User input from the `displayName` request parameter flows directly into HTML output without escaping.

## Source

Line 24 retrieves untrusted input:
```java
String displayName = request.getParameter("displayName");
```

The `displayName` parameter is controlled by the attacker via the request URL or POST data.

## Fix

Replace the vulnerable JSP scriptlet expression with JSTL's `<c:out>` tag to escape HTML special characters:

**Original (vulnerable):**
```jsp
<p>Welcome, <%= displayName %>!</p>
```

**Fixed:**
```jsp
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!-- ... rest of file ... -->
<p>Welcome, <c:out value="${displayName}"/>!</p>
```

The `<c:out>` tag with default escaping converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into HTML entities, preventing script injection.

## Explanation

The vulnerability occurs because the JSP scriptlet expression `<%= displayName %>` outputs the variable as-is into the HTML response. When an attacker crafts a request with `displayName=<script>alert('XSS')</script>`, the script tag renders directly in the browser and executes.

The JSTL `<c:out>` tag applies automatic HTML entity encoding. The same injected payload becomes `&lt;script&gt;alert('XSS')&lt;/script&gt;`, which renders as plain text instead of executing.

Ensure the JSTL Core library (standard JSP implementation) is available on the classpath. Most modern JSP containers include it by default.
