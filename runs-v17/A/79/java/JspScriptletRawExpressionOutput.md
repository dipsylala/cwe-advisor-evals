## Verdict
CONFIRMED. The vulnerability on line 30 outputs untrusted user input from `request.getParameter("displayName")` directly into HTML without escaping, allowing reflected XSS attacks.

## Source
- Parameter `displayName` is obtained from the request at line 24: `String displayName = request.getParameter("displayName");`
- This source is untrusted (attacker-controlled via URL/form parameter)
- The parameter flows without sanitization through line 25-27 (null check only)
- Line 30 is the sink: `<p>Welcome, <%= displayName %>!</p>` outputs it directly into HTML

## Fix
The fix escapes the output using JSTL's `<c:out>` tag, which HTML-encodes special characters (`<`, `>`, `&`, `"`, `'`) preventing script injection.

### File: welcome.jsp
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
            pageContext.setAttribute("displayName", displayName);
        %>
        <!-- SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement. -->
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
The fix makes two changes:

1. **Add JSTL import** (line 2): `<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>` brings in the Core JSTL tag library, which provides the `<c:out>` tag for safe output.

2. **Set page attribute** (line 31): `pageContext.setAttribute("displayName", displayName);` makes the scriptlet variable available to JSTL's EL expression language.

3. **Replace vulnerable output** (line 34): `<c:out value="${displayName}" />` replaces the unsafe `<%= displayName %>` expression. The `<c:out>` tag automatically HTML-escapes the value by default (`escapeXml="true"`), converting characters like `<` to `&lt;`, preventing injected scripts from executing.

An attacker payload like `?displayName=<img src=x onerror=alert('xss')>` is now rendered as harmless HTML text `&lt;img src=x onerror=alert('xss')&gt;` instead of executing JavaScript.
