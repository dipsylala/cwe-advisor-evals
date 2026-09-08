## Verdict

Exploitable. CWE-79 (Reflected Cross-Site Scripting), `welcome.jsp` line 30. Confidence: high.

## Source

- **Source**: `request.getParameter("displayName")` (line 24) - an HTTP request parameter, fully attacker-controlled. The only guard applied is a null check that substitutes the literal `"there"` when the parameter is absent (lines 25-27); no encoding or validation is applied to a supplied value.
- **Sink**: the JSP expression `<%= displayName %>` on line 30, which writes the scriptlet-local variable directly into the HTML response body between `<p>Welcome, ` and `!</p>`.
- **Flow**: source and sink are in the same scriptlet block with no intervening transformation, so a request such as `?displayName=<script>...</script>` is emitted verbatim into the page and executes in the victim's browser.

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

**Library recommendation**: `org.owasp.encoder:encoder` (OWASP Java Encoder), providing `org.owasp.encoder.Encode`. The loaded guidance does not carry a minimum safe version for this artifact, so none is stated here - resolve the version through SCA/dependency-check tooling before merging, and add it to the project's dependency manifest (e.g. `pom.xml` or `build.gradle`); no manifest file was included in this finding's call chain, so it is not shown here. `Encode.forHtml()` is the guidance-named method for this context (an HTML body text node).

## Explanation

The unencoded request parameter reaches the response body unmodified, so any HTML/script metacharacters an attacker supplies in `displayName` execute in the victim's browser (reflected XSS). The fix wraps the sink in `Encode.forHtml()` from the OWASP Java Encoder, which HTML-entity-encodes `<`, `>`, `&`, `"`, `'` and other characters significant to an HTML parser, so the value is always rendered as literal text rather than markup. This is the context-appropriate choice per the loaded guidance: the output lands in HTML body text (not an attribute, script block, URL, or CSS value), and `displayName` is a scriptlet-local Java variable rather than a request/session/application-scoped attribute, so JSTL `<c:out>` cannot resolve it via EL without first publishing it with `pageContext.setAttribute(...)` - keeping the existing scriptlet and wrapping the expression is the smaller, guidance-sanctioned change. The `null` substitution to `"there"` is unaffected: `Encode.forHtml("there")` returns `"there"` unchanged, so the default greeting is untouched.

## Behaviour changes

- Output for any `displayName` containing HTML-significant characters (`<`, `>`, `&`, `"`, `'`) now renders as escaped entities instead of raw markup. This is the intended effect of closing the weakness, not a side effect - previously a literal `<` or `&` in a legitimate display name (e.g. `Smith & Sons`, `<Guest>`) would already have been misinterpreted as HTML by the browser, so encoding also fixes that pre-existing rendering bug rather than introducing a new one.
- No other arguments, return values, or control flow changed; the null-check/default-value logic (lines 25-27) and the sink's discard behavior (nothing was previously captured from the raw expression) are preserved.
- Introduces a new compile-time dependency on `org.owasp.encoder:encoder` for the JSP's generated servlet class. This is a build-time behaviour change (the WAR now needs this jar on the classpath) but not a runtime behaviour change for legitimate input.

**Verification**: No JSP/servlet container or OWASP Encoder jar was available in this isolated single-file case to compile or execute against. Manual review: `Encode.forHtml(String)` is a documented static method of `org.owasp.encoder.Encode` (named directly in the loaded language guidance, so not taken from unverified recall); its single `String` parameter matches the existing `displayName` local exactly, and the only change to the file is that one expression plus the added `<%@ page import=... %>` directive, so no other call site or declaration needed updating.

**Assumptions**: The fix wraps the existing scriptlet rather than converting to JSTL `<c:out>`, per the guidance's own noted alternative for a scriptlet-local variable; publishing `displayName` via `pageContext.setAttribute` and switching to `<c:out>` was rejected as a larger diff with no additional security benefit. No dependency manifest was present in the call chain, so the `org.owasp.encoder:encoder` addition and its version are named as a prerequisite rather than shown as a file edit.
