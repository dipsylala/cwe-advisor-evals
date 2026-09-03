## Verdict

Confirmed. The `displayName` variable at line 30 is populated from `request.getParameter("displayName")` without validation or encoding, and is rendered directly into HTML via JSP expression `<%= displayName %>`. An attacker can inject arbitrary HTML and JavaScript by passing payloads such as `?displayName=<script>alert('XSS')</script>`, which will execute in the victim's browser context.

## Source

Line 24: `String displayName = request.getParameter("displayName");` — untrusted HTTP request parameter.

Line 30: `<p>Welcome, <%= displayName %>!</p>` — unencoded output sink. The JSP expression outputs the raw value directly into HTML body context.

Data flow: HTTP request → `getParameter()` → scriptlet variable → HTML page rendered to victim.

## Fix

Add the JSTL Core taglib declaration at the top of the file (after the existing `@page` directive):

```jsp
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
```

Replace line 30 from:

```jsp
<p>Welcome, <%= displayName %>!</p>
```

to:

```jsp
<p>Welcome, <c:out value="${displayName}" />!</p>
```

## Explanation

The fix replaces the raw JSP expression `<%= %>` with the JSTL `<c:out>` tag, which applies HTML entity encoding by default (`escapeXml="true"`). This encoding converts special HTML characters (`<`, `>`, `&`, quotes) into safe entities (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#039;`), preventing the browser from interpreting attacker-controlled input as executable code or markup.

The JSTL tag is the recommended escaping construct for JSP because it is explicit, defaults to safe encoding, and aligns with the context (HTML body content). The `${displayName}` expression is resolved from the scriptlet variable through the page scope, so no code logic changes.

## Behaviour changes

- HTML special characters in `displayName` are now escaped. If the parameter contains `<`, `>`, or `&`, these render as `&lt;`, `&gt;`, `&amp;` respectively (visible to the user as literal characters, not markup).
- Payloads like `<script>alert('XSS')</script>` are rendered as literal text rather than executed.
- Legitimate display names containing no HTML syntax are unaffected.
- The default greeting "there" (line 26) is unaffected.
