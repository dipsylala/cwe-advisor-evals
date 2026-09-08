## Verdict

Confirmed. Reflected cross-site scripting: the `displayName` request parameter is written into the HTML response with a raw JSP expression and no output encoding.

## Source

`request.getParameter("displayName")` in the scriptlet at the top of the `<main>` block (welcome.jsp, line 24). The value falls back to the literal `"there"` only when the parameter is absent; any other value, including HTML/JavaScript markup, passes through unchanged.

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
            pageContext.setAttribute("displayName", displayName);
        %>
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

The `<%= displayName %>` scriptlet expression writes the parameter value straight into the HTML body with no encoding, so a request like `?displayName=<script>...</script>` (or an `onerror`/`<img>` payload) executes in the victim's browser exactly as if it were part of the page markup.

The fix keeps the same data flow and the same "there" default, but stops emitting the value through a raw expression. It exposes `displayName` to the page scope with `pageContext.setAttribute(...)` and renders it with the JSTL core tag `<c:out value="${displayName}"/>`. `c:out`'s `escapeXml` attribute defaults to `true`, so `<`, `>`, `&`, `'` and `"` are all converted to their HTML entity equivalents before being written to the response - any markup or attribute-breaking characters in the parameter become inert text instead of being parsed as HTML. This is the standard JSP idiom for encoding untrusted output and requires only the JSTL core taglib (`jstl` / `javax.servlet.jsp.jstl`), which is already the conventional dependency for JSP view logic rather than a new addition specific to this fix.

No other part of the page reflects request input, so no further changes are needed.
