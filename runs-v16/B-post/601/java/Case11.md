## Verdict

exploitable

## Source

`data` string from Case11A, read via `BufferedReader.readLine()` from an external HTTP connection to `http://www.example.org/`. The value flows through Case11B → Case11C → Case11D.

## Fix

**Vulnerable code:**
```java
URI uri;
try
{
    uri = new URI(data);
}
catch (URISyntaxException exceptURISyntax)
{
    response.getWriter().write("Invalid redirect URL");
    return;
}

// SAST FINDING: CWE-601 (URL Redirection to Untrusted Site) reported here. Sink is the next statement.
response.sendRedirect(data);
```

**Fixed code:**
```java
URI uri;
try
{
    uri = new URI(data);
}
catch (URISyntaxException exceptURISyntax)
{
    response.getWriter().write("Invalid redirect URL");
    return;
}

// Validate redirect: reject URLs with external hosts or dangerous schemes
String host = uri.getHost();
if (host != null)
{
    // External URL - reject it
    response.getWriter().write("Redirect to external sites is not allowed");
    return;
}

String scheme = uri.getScheme();
if (scheme != null && (scheme.equalsIgnoreCase("javascript") || scheme.equalsIgnoreCase("data")))
{
    // Dangerous scheme - reject it
    response.getWriter().write("Invalid redirect URL");
    return;
}

// Safe to redirect - relative path only
response.sendRedirect(data);
```

## Explanation

The original code parses the untrusted URL to check syntax but then passes it directly to `response.sendRedirect()` without validating that the redirect target is safe. This allows an attacker-controlled URL (such as `https://attacker.com`) read from the external source to be used as a redirect destination, enabling phishing attacks.

The fix adds validation of the parsed URI object before redirecting. It rejects any redirect that specifies an external host (including scheme-relative URLs like `//evil.example`) or uses dangerous schemes like `javascript:` or `data:`. Only relative paths without an external host are permitted to proceed to the `sendRedirect()` call. This ensures redirects remain within the application's own server.

## Behaviour changes

1. **Rejection of external URLs**: The fixed code now rejects redirect URLs with a non-null host (external domains) by writing an error message instead of redirecting. Original code accepted these.
2. **Rejection of dangerous schemes**: The fixed code checks for and rejects `javascript:` and `data:` schemes explicitly. Original code would have passed these through if they parsed as valid URIs.
3. **Early return on validation failure**: When validation fails, the method returns after writing an error message, preventing the redirect. Original code would redirect regardless.
4. **All other redirects unchanged**: Relative paths with no external host (null host) are still redirected as before, preserving intended functionality for safe internal redirects.

The sink contract is preserved: `response.sendRedirect()` is still called with the same untrusted data, but only after validation ensures it is now a safe relative path with no external host. The return type and exception contract remain unchanged.
