## Verdict

XSS vulnerability confirmed. Line 30 outputs untrusted request parameter `displayName` without HTML entity encoding, allowing arbitrary HTML/JavaScript injection.

## Source

Line 24: `String displayName = request.getParameter("displayName");` – untrusted HTTP parameter

Line 30: `<p>Welcome, <%= displayName %>!</p>` – output sink with no encoding

Data flows directly from source to sink without validation or transformation.

## Fix

Add OWASP Java Encoder import and wrap output with context-appropriate encoding.

### File: welcome.jsp

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

The vulnerability allows XSS because user-controlled input is rendered directly into an HTML context without encoding. An attacker controlling the `displayName` parameter can inject script tags or event handlers that execute in the victim's browser.

**The fix applies two layers:**

1. **Import OWASP Java Encoder** at line 2 to access the encoding library
2. **Wrap output with `Encode.forHtml(displayName)`** at line 30 to encode special characters (`<`, `>`, `&`, `"`, `'`) into HTML entities

This ensures:
- `<script>alert('xss')</script>` becomes `&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;` (rendered as literal text)
- Legitimate content like names with `&` or `<` (e.g., "Smith & Jones") remain readable while safe
- The encoding is context-aware (HTML body context uses entity encoding, not URL or JavaScript encoding)

## Behaviour changes

**Legitimate input:**
- Input: `"Welcome, Smith & Jones!"`
- Before: Renders as "Welcome, Smith & Jones!" (ampersand unencoded)
- After: Renders as "Welcome, Smith &amp; Jones!" (ampersand encoded but visually identical)

**Attack payload:**
- Input: `"Welcome, <img onerror=alert('xss')>"`
- Before: Executes JavaScript alert (XSS vulnerability)
- After: Renders as "Welcome, &lt;img onerror=alert(&#x27;xss&#x27;)&gt;" (no script execution)

No functional regressions; legitimate content displays correctly while attack payloads are neutralized.
