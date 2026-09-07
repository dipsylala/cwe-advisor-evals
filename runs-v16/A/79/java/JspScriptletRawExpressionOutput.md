## Verdict

Confirmed. Line 30 outputs user-supplied input without escaping, creating a reflected XSS vulnerability.

## Source

The vulnerability originates at line 24, where `displayName` is retrieved directly from the request parameter without validation or sanitization:

```jsp
String displayName = request.getParameter("displayName");
```

This untrusted value flows directly to the HTML output sink on line 30.

## Fix

Replace the JSP expression output with JSTL's `<c:out>` tag, which performs HTML entity encoding by default:

```jsp
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
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
            <a href="/account/logout">Log out</a>
        </nav>
    </header>

    <main class="account-home">
        <%
            String displayName = request.getParameter("displayName");
            if (displayName == null) {
                displayName = "there";
            }
        %>
        <p>Welcome, <c:out value="${displayName}" />!</p>

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

The original code uses JSP scriptlet expression syntax `<%= displayName %>` to output the value directly into HTML. An attacker can inject JavaScript by crafting a request with a `displayName` parameter containing malicious script, such as `<script>alert('XSS')</script>` or an event handler like `" onmouseover="alert('XSS')`. The browser interprets this injected script as part of the page, executing attacker-controlled code in the victim's session.

The fix uses JSTL's `<c:out>` tag, which automatically HTML-encodes the output value, converting characters like `<`, `>`, `&`, and `"` to their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`). This ensures that any user input is rendered as literal text rather than interpreted as HTML or JavaScript, neutralizing the XSS attack vector.

The JSTL taglib directive must be added at the top of the JSP file to make `<c:out>` available.
