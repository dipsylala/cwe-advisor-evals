## Verdict

Exploitable

## Source

External untrusted data source: HTTP response body read from `http://www.example.org/` in Case10A (line 38), passed as the `data` parameter to Case10B.handleSink().

## Fix

**Vulnerable code (Case10B, lines 14-36):**

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
        
        // SAST FINDING: CWE-601 (URL Redirection to Untrusted Site) reported here.
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
        
        // Reject external redirects: non-null host indicates absolute or scheme-relative URL
        if (uri.getHost() != null)
        {
            response.getWriter().write("External redirects are not allowed");
            return;
        }
        
        // Reject dangerous schemes (javascript:, data:) - absolute URI with null host
        if (uri.isAbsolute())
        {
            response.getWriter().write("Invalid redirect URL");
            return;
        }
        
        // Only redirect to relative paths
        response.sendRedirect(data);
        return;
    }
}
```

## Explanation

The original code validated only that the input was syntactically valid as a URI, but did not prevent redirects to external domains. An attacker could supply any valid absolute URL (e.g., `https://attacker.com`) and the application would redirect users to the attacker's site. The fixed code adds validation to reject external redirects by checking the parsed URI's host component. If `getHost()` returns non-null, the URL is either absolute (with a scheme and host) or scheme-relative (e.g., `//evil.com`), both of which are external and rejected. The code also rejects absolute URIs with null hosts (e.g., `javascript:alert(1)`) to prevent dangerous schemes. Only relative paths (host is null and not absolute) are allowed to pass through to `sendRedirect()`, preventing open redirect attacks while preserving the application's ability to redirect within its own domain.

## Behaviour changes

The fixed code adds two validation branches that reject the redirect and return an error message instead of redirecting:
1. When the parsed URI has a non-null host (external URL or scheme-relative reference), a "not allowed" message is sent.
2. When the parsed URI is absolute with null host (dangerous schemes like `javascript:` or `data:`), an "invalid URL" message is sent.

These changes alter the original behavior by preventing some redirects that would have succeeded. This is an intentional security restriction - the sink contract (accepting any syntactically valid URI string) is replaced with a stricter contract (accepting only relative paths). External and dangerous redirects now fail safely with an error response instead of executing the open redirect.
