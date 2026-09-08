## Verdict

Exploitable. Untrusted input from `request.getParameter("displayName")` flows directly into HTML output via JSP expression without encoding, allowing arbitrary script injection.

## Source

Line 24: `String displayName = request.getParameter("displayName");`

The `request.getParameter()` call reads user-controlled input from the HTTP request query string or form data. No validation or encoding is applied before storage in the local variable. A null check (lines 25-27) substitutes a safe default only if the parameter is absent, but does not sanitize hostile input.

## Fix

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

The vulnerability is closed by applying HTML entity encoding to `displayName` at the output sink (line 30). The fix adds a page-level import for the OWASP Java Encoder library (`org.owasp.encoder.Encode`) and wraps the untrusted variable with `Encode.forHtml()`, which escapes all characters that have special meaning in HTML content (`<`, `>`, `&`, `'`, `"`). This prevents the browser from interpreting any injected markup or script as executable code. An attacker-supplied payload like `<script>alert('xss')</script>` is rendered as literal text: `&lt;script&gt;alert('xss')&lt;/script&gt;`. The encoding is applied specifically to the HTML body context where the value appears; no change is needed to input validation or storage, since the defense occurs at output.

## Behaviour changes

None. The `Encode.forHtml()` method takes a String and returns an HTML-encoded String of the same logical content. The encoded output still renders the user's display name correctly in the browser; only characters with HTML syntax significance are escaped. The caller's responsibility to check for null (lines 25-27) remains unchanged, and the fallback to "there" is still performed before encoding. Response encoding (character set), HTTP headers, and request parameter reading are unaffected.
