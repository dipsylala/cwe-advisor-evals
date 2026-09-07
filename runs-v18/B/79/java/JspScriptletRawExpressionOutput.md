## Verdict

Exploitable. Untrusted user input from `request.getParameter("displayName")` is output directly into HTML body context via JSP expression syntax without any encoding, allowing an attacker to inject arbitrary HTML/JavaScript that executes in victims' browsers.

## Source

- **Source**: Line 24 - `String displayName = request.getParameter("displayName");` obtains untrusted user-controlled input from HTTP request parameters
- **Sink**: Line 30 - `<%= displayName %>` renders the value directly into HTML page content without encoding
- **Data flow**: Direct pass-through. The parameter is conditionally set to "there" on null (line 25-27), but no encoding or validation is applied before output.

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

The vulnerability exists because the JSP `<%= displayName %>` expression outputs user-controlled data directly into HTML content without any encoding. An attacker supplying `displayName=<img src=x onerror="alert('XSS')">` or `displayName=<script>alert('XSS')</script>` would cause arbitrary JavaScript to execute in victims' browsers, enabling session theft, credential harvesting, or malware distribution.

The fix applies OWASP Java Encoder's `Encode.forHtml()` method to the output at the sink. This method HTML-entity-encodes special characters (`<` to `&lt;`, `>` to `&gt;`, `&` to `&amp;`, `"` to `&#x22;`, `'` to `&#x27;`) so malicious markup is rendered as inert text rather than interpreted as tags or script. This is the context-appropriate encoding for HTML body content, required by the guidance since JSP has no auto-escape setting.

The fix also adds the required import statement `<%@ page import="org.owasp.encoder.Encode" %>`. The OWASP Java Encoder library (artifact `org.owasp.encoder:encoder`) must be added to the project's build dependencies if not already present; confirm the resolved version against SCA tooling before merging.

## Behaviour changes

- An attacker payload such as `<img src=x onerror="alert('XSS')">` is now rendered as literal text `&lt;img src=x onerror=&#x22;alert(&#x27;XSS&#x27;)&gt;` instead of executing as a tag. This closes the XSS vector.
- Legitimate display names containing special characters (e.g., "Alice & Bob", "O'Reilly", "test<name>") render correctly as plain text. The browser's HTML parser decodes the entities for display while treating them as data, not markup.
- No change to intended functionality: users are still greeted with their display name; the fix only prevents injection.
- The return type and output of `Encode.forHtml()` is a String, matching the `<%= %>` expression's contract, so no downstream code changes are required.
