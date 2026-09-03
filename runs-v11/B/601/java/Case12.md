## Verdict

Exploitable. The `data` parameter flows from Case12A (external data source) through the call chain (Case12B → Case12C → Case12D) to Case12E, where it is passed directly to `response.sendRedirect()` without validating the redirect target's safety.

## Source

The `data` variable in Case12A.java, populated by reading from an external URL connection (`http://www.example.org/`). This untrusted data flows unchanged through the intermediate handlers (Case12B, Case12C, Case12D) to the sink in Case12E.

## Fix

**Vulnerable code** (Case12E.java, lines 14-36):
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
        
        // SAST FINDING: CWE-601 (URL Redirection to Untrusted Site) reported here. Sink is the next statement.
        response.sendRedirect(data);
        return;
    }
}
```

**Fixed code**:
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
        
        // Reject redirects to external URLs or absolute URIs
        // Only allow relative paths (no scheme or host)
        if (uri.getScheme() != null || uri.getHost() != null)
        {
            response.getWriter().write("Redirects to external URLs are not allowed");
            return;
        }
        
        response.sendRedirect(data);
        return;
    }
}
```

## Explanation

The fix adds a validation step after URI parsing to ensure only relative paths are allowed for redirects. By checking that both `uri.getScheme()` and `uri.getHost()` are null, the code rejects any absolute URIs and external domain redirects. This aligns with the CWE-601 guidance principle to "reject redirects to external domains by default" and use the `getHost()` check rather than `isAbsolute()` to correctly identify scheme-relative URLs like `//evil.com` as unsafe. The vulnerability is closed because an attacker cannot redirect users to an external site; only application-controlled relative paths are permitted.

## Behaviour changes

The fix adds an additional validation and error response path. When a malicious or external URL is detected, the code now writes "Redirects to external URLs are not allowed" to the response and returns early, preventing the redirect. This changes the response body compared to the original code (which would have silently redirected). The original code's contract for valid relative URLs remains intact—such URLs are still redirected as before. No other parameters or return values are altered.
