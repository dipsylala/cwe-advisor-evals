## Verdict
Confirmed CWE-601: URL Redirection to Untrusted Site

## Source
Case11A reads untrusted data from an external URL (http://www.example.org/) via `BufferedReader.readLine()`. This data flows through Case11B and Case11C to Case11D.

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
        
        // Validate that redirect targets this application only
        String scheme = uri.getScheme();
        String host = uri.getHost();
        
        // Allow only relative URLs or same-origin redirects
        if (host != null && !host.equalsIgnoreCase(request.getServerName()))
        {
            response.getWriter().write("Redirect to external hosts not allowed");
            return;
        }
        
        if (scheme != null && !scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))
        {
            response.getWriter().write("Invalid URL scheme");
            return;
        }
        
        response.sendRedirect(data);
        return;
    }
}
```

## Explanation
The original code validated URI syntax but did not restrict where redirects go. An attacker could supply a valid external URL like `http://attacker.com/` to redirect users to a malicious site.

The fix adds origin validation: it extracts the host from the parsed URI and verifies it matches the current request's server name. This ensures redirects stay within the application. Relative URLs (no host) are also allowed since they implicitly target the same origin. Additionally, the scheme is checked to reject dangerous protocols like `javascript:` or `data:`.

This approach follows the allowlist pattern: only same-origin redirects are permitted.
