## Verdict
exploitable

## Source
`data = readerBuffered.readLine()` in Case12A.java, line 38. External data read from `http://www.example.org/` is passed through the call chain (Case12B → Case12C → Case12D → Case12E) without validation.

## Fix

**Vulnerable code (Case12E.java, lines 17-34):**
```java
if (data != null)
{
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
    return;
}
```

**Fixed code:**
```java
if (data != null)
{
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
    
    // Validate redirect destination: reject absolute URLs with hosts,
    // allow only relative paths (no host) or whitelisted domains
    if (uri.getHost() != null)
    {
        // Absolute URL with host - reject unless in allowlist
        response.getWriter().write("Redirect to external domains not allowed");
        return;
    }
    
    if (uri.isAbsolute() && uri.getHost() == null)
    {
        // Absolute URI with no host (e.g., javascript:, data:) - reject
        response.getWriter().write("Invalid redirect URL");
        return;
    }
    
    // Safe to redirect: relative path only
    response.sendRedirect(data);
    return;
}
```

## Explanation
The vulnerability existed because the code validated that `data` was a valid URI format but then passed the untrusted string directly to `sendRedirect()` without checking whether it was a safe redirect destination. An attacker could provide any absolute URL (e.g., `http://attacker.com`) from the external data source, and the application would redirect users there.

The fix adds two validation checks after URI parsing:
1. **Host validation** - If the URI has a non-null host (detected via `getHost()`), it is an absolute URL pointing to an external domain and is rejected. This catches URLs like `http://attacker.com` and scheme-relative URLs like `//attacker.com`.
2. **Opaque URI rejection** - If the URI is absolute but has no host (e.g., `javascript:alert(1)` or `data:text/html,...`), it is rejected outright to prevent script injection attacks.

Only relative paths (with null host and non-absolute) are allowed to proceed to `sendRedirect()`. This ensures that redirects stay within the application domain. For production code, external redirects can be re-enabled by checking against an allowlist of trusted domains, but the default is to reject external destinations.

## Behaviour changes
The fix adds two new rejection paths before calling `sendRedirect()`:
- Absolute URLs with non-null hosts are now rejected with error message "Redirect to external domains not allowed"
- Absolute URIs with null hosts (like `javascript:` schemes) are rejected with error message "Invalid redirect URL"

These changes prevent redirects to external domains and script injection attacks. The application no longer displays redirect behavior for untrusted external URLs; instead it returns an error message to the client. This is a breaking change only for cases where the application intentionally needs to redirect to external sites—in those cases, the allowlist approach described in the explanation should be implemented with specific trusted domain validation via `getHost()` comparison.
