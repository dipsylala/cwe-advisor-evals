## Verdict

CWE-79 confirmed. The `displayName` parameter is retrieved from user input via `request.getParameter()` and output directly into HTML content without encoding on line 30, allowing XSS injection.

## Source

```jsp
<%
    String displayName = request.getParameter("displayName");
    if (displayName == null) {
        displayName = "there";
    }
%>
<!-- SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement. -->
<p>Welcome, <%= displayName %>!</p>
```

The source is `request.getParameter("displayName")` (line 24), treated as untrusted external data. The sink is the JSP expression `<%= displayName %>` on line 30, which outputs the value directly into HTML context without encoding.

## Fix

Apply HTML entity encoding to the output using OWASP Java Encoder:

```jsp
<%@ page import="org.owasp.encoder.Encode" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
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
            String displayName = request.getParameter("displayName");
            if (displayName == null) {
                displayName = "there";
            }
        %>
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

The JSP scriptlet expression `<%= %>` is a direct output sink that does not perform any encoding by default. When untrusted user input (from `request.getParameter()`) reaches this sink, an attacker can inject HTML or JavaScript that will execute in the victim's browser.

**The fix applies context-aware output encoding:**

- `Encode.forHtml()` from OWASP Java Encoder encodes characters that have special meaning in HTML body content: `<` becomes `&lt;`, `>` becomes `&gt;`, `&` becomes `&amp;`, and quotes become `&#x27;` and `&quot;` respectively
- This ensures that if an attacker submits `<script>alert('XSS')</script>` as the `displayName` parameter, it renders as literal text in the HTML page, not as executable code
- The encoding is applied at the output sink (line 30), the standard practice in Java applications

OWASP Java Encoder is the recommended tool because:
- It provides context-specific encoding methods (`forHtml()`, `forHtmlAttribute()`, `forJavaScript()`, etc.)
- It is maintained and security-focused
- Spring's `HtmlUtils` is insufficient for this use case because it lacks methods for attributes, JavaScript, URLs, and CSS contexts

The import statement `<%@ page import="org.owasp.encoder.Encode" %>` must be added at the top of the JSP file to access the encoder.

## Behaviour changes

- **Before:** A request parameter `displayName=<script>alert('XSS')</script>` would render as executable JavaScript and execute in the victim's browser
- **After:** The same payload renders as the literal text `<script>alert('XSS')</script>` displayed on the page, with no script execution
- **Legitimate content:** User names containing special characters like `"O'Brien"` or `"A & B"` now render correctly as `&quot;O&#x27;Brien&quot;` and `A &amp; B` respectively, displaying as `"O'Brien"` and `A & B` in the browser
- **Performance:** Negligible; encoder overhead is microseconds per call
