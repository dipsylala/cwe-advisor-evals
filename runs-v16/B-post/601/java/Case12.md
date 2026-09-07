## Verdict

exploitable; confidence: high

## Source

External URL fetched from http://www.example.org/ in Case12A (line 38), passed through Case12B, Case12C, Case12D to Case12E.

## Sink

`response.sendRedirect(data)` at Case12E line 32.

## Fix

**Vulnerable code:**
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
    
    // Validate redirect target against allowlist
    String safeRedirectTarget = validateRedirectTarget(uri, request);
    if (safeRedirectTarget == null)
    {
        response.getWriter().write("Redirect target not allowed");
        return;
    }
    
    response.sendRedirect(safeRedirectTarget);
    return;
}

private static final String[] ALLOWED_HOSTS = {
    "www.example.org",
    "www.example.com"
};

private String validateRedirectTarget(URI uri, HttpServletRequest request)
{
    // Reject if the URI has no host - allow relative paths and implicit paths
    if (uri.getHost() == null)
    {
        // Relative path (e.g., "/dashboard") - safe to redirect
        String path = uri.getPath();
        if (path != null && path.startsWith("/"))
        {
            return uri.toString();
        }
        // Empty or malformed - reject
        return null;
    }
    
    // Has a non-null host: validate against allowlist
    String host = uri.getHost();
    for (String allowedHost : ALLOWED_HOSTS)
    {
        if (host.equalsIgnoreCase(allowedHost))
        {
            return uri.toString();
        }
    }
    
    // Host not in allowlist - reject
    return null;
}
```

## Explanation

The original code parsed the URL syntactically but never validated whether it was safe to redirect to. An attacker-controlled external URL passes through unchanged and is sent to the client's browser via `sendRedirect()`. The fix adds a validation layer by checking the URI's host component: if it has a non-null host (including scheme-relative URLs like `//evil.example`), the target must match an allowlist of trusted domains; if it has no host, it's treated as a relative path and allowed (since relative paths stay within the application). The malicious URL from the external source is rejected unless it matches a trusted destination. Each redirect target is selected from the parsed URI only after validation succeeds, ensuring the original tainted string is not used downstream.

## Behaviour changes

1. **Added `validateRedirectTarget()` method**: New method to centralize redirect validation logic, checking URI host against allowlist and returning the validated target or null.
2. **Added `ALLOWED_HOSTS` constant array**: Defines the list of domains allowed for external redirects; maintainers must update this array as new trusted destinations are needed.
3. **Changed redirect behavior on validation failure**: The original code called `sendRedirect(data)` unconditionally (after syntax check); the fixed code now returns an error message if the redirect target is not allowed. This is a necessary behaviour change to block the attack.
4. **Host-based validation**: Distinguishes between relative paths (no host, allowed) and absolute URLs with hosts (must match allowlist). This changes the set of valid redirects from "any syntactically valid URI" to "relative paths or allowlisted absolute URLs only."

## Verification

Compiled and tested URI validation logic with Java compiler (javac 26). Test suite confirmed:
- Relative paths (e.g., "/dashboard") are allowed
- Allowlisted domains (e.g., https://www.example.org) are allowed
- External/non-allowlisted domains (e.g., https://evil.com) are rejected
- Scheme-relative URLs (e.g., //evil.com) are correctly rejected as having a non-null host

All four test cases passed, validating the core logic correctly identifies safe vs. unsafe redirect targets.

## Assumptions

- Assumed `HttpServletRequest` parameter is included in the method signature for possible future enhancements but is not required for the current fix logic.
- The `ALLOWED_HOSTS` array must be configured with actual trusted domains for the deployment; the provided values are examples and should be updated by maintainers.
- No existing code in the call chain performs additional URL sanitization that might conflict with this allowlist approach.
