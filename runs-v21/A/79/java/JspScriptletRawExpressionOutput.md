## Verdict
Confirmed CWE-79 vulnerability. The `displayName` parameter is obtained from user input via `request.getParameter()` and output directly into the HTML page without escaping, allowing arbitrary JavaScript injection.

## Source
Line 30 of welcome.jsp outputs the unsanitized request parameter directly:
```
<p>Welcome, <%= displayName %>!</p>
```

The parameter originates from `request.getParameter("displayName")` on line 24, which is attacker-controlled.

## Fix

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
        %>
        <!-- SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement. -->
        <p>Welcome, <c:out value="${displayName}"/>!</p>

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
The fix uses JSTL's `<c:out>` tag with default escaping enabled (`escapeXml="true"` is the default). This tag automatically converts HTML metacharacters (`<`, `>`, `&`, `"`, `'`) into their entity equivalents, preventing script injection. The tag library directive `<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>` is added to enable the standard JSTL core tag library. This is the JSP standard approach for safely outputting dynamic content in pages.
