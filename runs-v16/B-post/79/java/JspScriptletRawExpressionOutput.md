## Verdict
Exploitable. Untrusted user input from the request parameter `displayName` flows directly to HTML output via JSP expression without encoding, allowing script injection.

## Source
Line 24: `String displayName = request.getParameter("displayName");`

User-controlled request parameter, untrusted input source.

## Fix
**Vulnerable code (line 30):**
```jsp
<p>Welcome, <%= displayName %>!</p>
```

**Fixed code:**
```jsp
<%@ page import="org.owasp.encoder.Encode" %>
...
<p>Welcome, <%= Encode.forHtml(displayName) %>!</p>
```

**Library requirement:**
Add OWASP Java Encoder to project dependencies (e.g., Maven `pom.xml`):
```xml
<dependency>
  <groupId>org.owasp.encoder</groupId>
  <artifactId>encoder</artifactId>
  <version>1.2.3</version>
</dependency>
```

## Explanation
The vulnerability exists because the JSP expression `<%= displayName %>` renders the untrusted request parameter directly into HTML content without encoding. An attacker can supply payloads like `?displayName=<img src=x onerror="alert(1)">` to execute arbitrary JavaScript in the victim's browser.

The fix applies context-specific HTML entity encoding using OWASP Java Encoder's `Encode.forHtml()` method at the output sink. This converts dangerous characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), ensuring the input is treated as data rather than executable markup. The JSP `import` directive makes the encoder class available in the scriptlet.

## Behaviour changes
None. `Encode.forHtml()` preserves the original string value while encoding only the characters that have special meaning in HTML context. The output remains readable and functional—a name containing `&`, `<`, or quotes renders correctly as escaped text rather than as markup or script.
