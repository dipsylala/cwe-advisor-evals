## Verdict

Exploitable. Untrusted user input from `request.getParameter("displayName")` flows directly to the JSP output sink without encoding, enabling HTML/JavaScript injection.

## Source

`String displayName = request.getParameter("displayName");` (line 24)

The `displayName` parameter is read from the HTTP request without validation or sanitization. It is then output directly into HTML content on line 30.

## Fix

**Library Recommendation:** OWASP Java Encoder. Ensure the dependency is present in your build (typically `org.owasp.encoder:encoder` in Maven or equivalent in Gradle/other build systems).

**Vulnerable Code (line 30):**
```jsp
<p>Welcome, <%= displayName %>!</p>
```

**Fixed Code:**
1. Add the import at the top of the JSP file (after the existing `page` directive):
```jsp
<%@ page import="org.owasp.encoder.Encode" %>
```

2. Replace line 30 with:
```jsp
<p>Welcome, <%= Encode.forHtml(displayName) %>!</p>
```

## Explanation

The vulnerability occurs because the `displayName` variable is rendered directly into HTML context without output encoding. An attacker can inject a URL parameter such as `?displayName=<img src=x onerror=alert(1)>` which executes arbitrary JavaScript in the victim's browser.

The fix applies context-aware output encoding using OWASP Java Encoder's `Encode.forHtml()` method at the output sink. This method encodes the string for safe inclusion in HTML body text by converting special characters (`<`, `>`, `&`, `'`, `"`) to their corresponding HTML entities (`&lt;`, `&gt;`, `&amp;`, `&#x27;`, `&quot;`). This ensures the injected payload is rendered as literal text rather than executable code, while preserving the readability of legitimate display names containing these characters.

## Behaviour changes

The only change is that special characters in the display name are now encoded. For example:
- Input `John & Jane` renders as `John &amp; Jane` (visually identical)
- Input `<script>alert(1)</script>` renders as `&lt;script&gt;alert(1)&lt;/script&gt;` (displayed as text)
- Input `User "Admin"` renders as `User &quot;Admin&quot;` (visually identical)

This encoding is transparent to legitimate users but blocks script injection. The parameter's default fallback to `"there"` remains unchanged, and no other application logic is affected.
