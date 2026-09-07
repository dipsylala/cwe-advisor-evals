## Verdict

Exploitable. The data variable is sourced from a remote HTTP connection (Case10A.java line 38) and flows directly to `response.sendRedirect()` without validation of the redirect destination. While URI syntax is checked, this does not prevent open redirects to external domains or dangerous schemes like `javascript:`.

## Source

Case10A.java line 38: `data = readerBuffered.readLine()` — reads untrusted input from a remote HTTP connection and passes it through Case10B.handleSink() to the redirect sink.

## Fix

**Vulnerable code (Case10B.java lines 14-36):**

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

**Fixed code:**

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
        
        // Validate redirect target: reject external domains and dangerous schemes
        String scheme = uri.getScheme();
        String host = uri.getHost();
        
        // Reject javascript: and data: schemes
        if ("javascript".equalsIgnoreCase(scheme) || "data".equalsIgnoreCase(scheme))
        {
            response.getWriter().write("Invalid redirect URL");
            return;
        }
        
        // If the URI has a host (absolute or scheme-relative), validate against allowlist
        if (host != null)
        {
            // Define allowlist of trusted domains for redirects
            String[] trustedDomains = {"www.example.org", "example.org", "localhost", "127.0.0.1"};
            boolean isTrusted = false;
            for (String domain : trustedDomains)
            {
                if (host.equalsIgnoreCase(domain))
                {
                    isTrusted = true;
                    break;
                }
            }
            
            if (!isTrusted)
            {
                response.getWriter().write("Invalid redirect URL");
                return;
            }
        }
        
        response.sendRedirect(data);
        return;
    }
}
```

## Explanation

The fix adds three layers of validation before calling `response.sendRedirect()`. First, it rejects URIs with dangerous schemes (`javascript:` and `data:`) which can execute code or leak data regardless of domain. Second, it checks whether the URI has a host component — determined by calling `URI.getHost()`, which correctly identifies both absolute URLs and scheme-relative URLs (`//evil.example`) that lack an explicit scheme. For any URI with a non-null host, the fix validates it against a whitelist of trusted domains using case-insensitive matching. URIs with a null host (relative paths like `/dashboard` or `./page`) are permitted as they remain scoped to the application server. This approach preserves the original method's contract — `response.sendRedirect()` still receives a valid URI string and operates identically — while ensuring only redirects to trusted destinations are executed. The validation rejects the finding by blocking untrusted external URLs before they reach the sink.

## Behaviour changes

The fix adds validation logic that may reject previously-accepted redirect targets:
- Any redirect to a host not in `trustedDomains` is now rejected with an error message instead of executing.
- Redirects using `javascript:` or `data:` schemes are rejected with an error message.
- Relative redirects (null host) continue to work without change.
- The method signature and return type remain unchanged; `response.sendRedirect()` is still called identically for approved destinations.

These changes are intentional security hardening to eliminate the open redirect vulnerability. The allowlist should be updated to include any additional trusted domains the application actually needs to redirect to.
