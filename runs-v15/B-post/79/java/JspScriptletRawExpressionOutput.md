## Verdict

Real XSS vulnerability confirmed. The request parameter `displayName` is output directly into HTML body text without encoding, allowing arbitrary script injection.

## Source

The untrusted data originates from `request.getParameter("displayName")` at line 24 and is output directly at line 30 without encoding:

```jsp
String displayName = request.getParameter("displayName");
if (displayName == null) {
    displayName = "there";
}
```

Then rendered as:
```jsp
<p>Welcome, <%= displayName %>!</p>
```

## Fix

Apply HTML entity encoding at the output sink using OWASP Java Encoder. Add the `page` directive to import the encoder, then wrap the expression:

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.owasp.encoder.Encode" %>
<!DOCTYPE html>
<html>
<head>
    <title>Account Home</title>
    <link rel="stylesheet" href="/static/css/account.css">
</head>
<body>
    <header class="site-header">
        <a class="logo" href="/">Acme Portal</a>
        <nav>
            <a href="/account/profile">Profile</a>
            <a href="/account/settings">Settings</a>
            <a href="/logout">Log out</a>
        </nav>
    </header>

    <main class="account-home">
        <%
            // The account setup wizard stores the chosen display name on the
            // profile, but a first-time visitor arriving straight from SSO
            // provisioning may not have one yet, so it is passed through as a
            // request parameter and greeted inline until the profile is saved.
            String displayName = request.getParameter("displayName");
            if (displayName == null) {
                displayName = "there";
            }
        %>
        <!-- SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement. -->
        <p>Welcome, <%= Encode.forHtml(displayName) %>!</p>

        <section class="dashboard-widgets">
            <div class="widget" id="recent-activity">
                <h2>Recent Activity</h2>
                <p>No activity to show yet.</p>
            </div>
            <div class="widget" id="quick-links">
                <h2>Quick Links</h2>
                <ul>
                    <li><a href="/account/billing">Billing</a></li>
                    <li><a href="/account/security">Security</a></li>
                </ul>
            </div>
        </section>
    </main>

    <footer class="site-footer">
        <p>&copy; 2026 Acme Corp.</p>
    </footer>
</body>
</html>
```

## Explanation

The fix adds two elements:

1. **Import statement:** `<%@ page import="org.owasp.encoder.Encode" %>` makes the OWASP Java Encoder available within the JSP.

2. **Context-specific encoding at the sink:** `Encode.forHtml(displayName)` converts special characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This renders the user input as literal text rather than executable HTML or script.

The encoder is the recommended approach for Java applications because it:
- Provides context-specific encoding methods (`forHtml()`, `forHtmlAttribute()`, `forJavaScript()`, etc.)
- Is maintained by OWASP and handles edge cases correctly
- Avoids character-by-character manual escaping, which is error-prone

Since the data appears in an HTML body context (between `<p>` tags), `Encode.forHtml()` is the appropriate choice.

## Behaviour changes

**Before fix:**
- User input `displayName=<script>alert('xss')</script>` results in script execution
- User input `displayName=<img src=x onerror=alert('xss')>` results in event handler execution
- Legitimate user names containing `<` or `&` display incorrectly

**After fix:**
- User input `displayName=<script>alert('xss')</script>` displays as literal text: `Welcome, &lt;script&gt;alert('xss')&lt;/script&gt;!`
- User input `displayName=<img src=x onerror=alert('xss')>` displays as literal text, no event handler executes
- Legitimate user names containing `<` and `&` display correctly as encoded entities
- XSS payloads are rendered harmless while maintaining readability and correct HTML semantics
