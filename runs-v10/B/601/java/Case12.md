## Verdict

Exploitable. Untrusted input from an external data source flows through the call chain (Case12A → Case12B → Case12C → Case12D → Case12E) and reaches `response.sendRedirect()` without validation that the destination is trusted. The code validates URI syntax (line 23 throws on `URISyntaxException`) but does not validate that the redirect target is safe—an attacker-controlled external URL will be accepted and executed.

## Source

External URL read from `http://www.example.org/` via `BufferedReader.readLine()` in Case12A.java, line 38. This untrusted data propagates through all five case files to Case12E.handleSink(), where it becomes the parameter `data`.

## Fix

```java
public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
{
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
        
        // Validate redirect destination is safe
        if (!isRedirectAllowed(uri, data))
        {
            response.getWriter().write("Redirect destination not allowed");
            return;
        }
        
        response.sendRedirect(data);
        return;
    }
}

private boolean isRedirectAllowed(URI uri, String originalUrl)
{
    // Reject opaque URIs (e.g., javascript:, data:) which are absolute but have no host
    if (uri.isAbsolute() && uri.getHost() == null)
    {
        return false;
    }
    
    // Reject scheme-relative URLs (e.g., //evil.com) by checking for non-null host
    if (uri.getHost() != null)
    {
        return false;
    }
    
    // Allow relative paths only (e.g., /dashboard, /login)
    return true;
}
```

## Explanation

The vulnerability arises because `response.sendRedirect()` at line 32 accepts user-controlled input without validating the redirect target. Although the code checks that the input is syntactically valid as a URI, it does not restrict the destination to trusted URLs. The fix adds an allowlist validation function `isRedirectAllowed()` that:

1. Rejects opaque URIs (absolute URIs with no host like `javascript:alert(1)`) by checking `uri.isAbsolute() && uri.getHost() == null`.
2. Rejects scheme-relative and absolute external URLs (those with a non-null host like `//evil.com` or `https://attacker.com`) by checking `uri.getHost() != null`.
3. Allows only relative paths (no host), which are scoped to the application's own domain.

This approach follows the guidance principle to "reject external URLs by default" and use "context-relative paths instead of accepting full URLs." The validation happens before the redirect is issued, so only safe destinations are reached.

## Behaviour changes

- **Added `isRedirectAllowed()` method**: New private method that encapsulates redirect validation logic. No impact on existing behaviour—only blocks redirects that should have been blocked anyway.
- **Added validation call before redirect**: Line 31-34 (new) calls `isRedirectAllowed()` and returns an error message if the URL is not allowed. Changes behaviour by rejecting external and scheme-relative URLs, returning HTTP response with message "Redirect destination not allowed" instead of redirecting.
- **Error message on validation failure**: Returns "Redirect destination not allowed" to the client instead of proceeding with the redirect. This is an intentional security hardening that prevents the redirect to an untrusted site.
- **No change to redirect call itself**: The `response.sendRedirect(data)` call is identical to the original; only the validation gate preceding it differs.
