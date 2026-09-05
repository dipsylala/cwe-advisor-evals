## Verdict

Exploitable

## Source

External input: `data` parameter originates from Case12A, which reads a line from `http://www.example.org/` via `URLConnection.getInputStream()` and passes it through Case12B, Case12C, and Case12D to Case12E.

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

// Reject absolute URIs with null host (javascript:, data:, etc.)
if (uri.isAbsolute() && uri.getHost() == null)
{
    response.getWriter().write("Invalid redirect URL");
    return;
}

// Reject URLs with a host (external domains and scheme-relative URLs like //evil.com)
if (uri.getHost() != null)
{
    response.getWriter().write("Invalid redirect URL");
    return;
}

// Only allow relative paths (no scheme, no host)
response.sendRedirect(data);
```

## Explanation

The vulnerability exists because `sendRedirect()` is called with user-controlled input (`data`) without validating that the destination is a trusted location. The initial URI syntax check catches malformed URLs but does not prevent redirects to attacker-controlled domains. The fix adds validation to ensure the redirect target is always a relative path (no host and no scheme) by checking the parsed URI object. If the URI has a host (indicating an external domain or scheme-relative URL like `//attacker.com`), or if it is absolute but has a null host (like `javascript:alert(1)`), the request is rejected. This allows only context-relative paths (e.g., `/dashboard`, `pages/success.html`) while blocking open redirects to external sites and dangerous schemes.

## Behaviour changes

The fix adds two additional validation checks before the redirect is issued. If `data` represents an external URL or a dangerous scheme, `sendRedirect()` is not called and the error message "Invalid redirect URL" is written to the response instead. This changes behavior for any non-relative URLs that previously would have been allowed through to the redirect sink. Legitimate use cases that depend on cross-domain redirects or absolute URLs would need an allowlist added (e.g., checking against a whitelist of approved external domains in an additional branch before the host-based rejection). The fix preserves the original response message and does not alter the servlet contract for normal (relative) redirects.
