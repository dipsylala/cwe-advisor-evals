## Verdict

Exploitable. The application accepts an untrusted `data` parameter and passes it directly to `response.sendRedirect()` without validating that the destination is a trusted, allowlisted destination. An attacker can craft a URL pointing to a malicious site and trick users into following the redirect from the trusted application domain.

## Source

Case19A.java passes `data` (in real scenarios, user-controlled input from HTTP parameters) to Case19B.handleSink().

## Fix

**Vulnerable Code (Case19B.java, line 32):**
```java
// SAST FINDING: CWE-601 (URL Redirection to Untrusted Site) reported here. Sink is the next statement.
response.sendRedirect(data);
```

**Fixed Code:**
```java
// Define allowlisted safe redirect destinations
private static final Set<String> SAFE_REDIRECTS = new HashSet<>(Arrays.asList(
    "/dashboard",
    "/profile",
    "/settings",
    "/home"
));

public void handleSink(String data, HttpServletRequest request, HttpServletResponse response) throws Throwable
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
        
        // Validate that the redirect destination is either a relative path in the allowlist
        // or reject it if it attempts to redirect to an external domain
        if (uri.getHost() != null) {
            // URI has an authority component (domain); reject external redirects
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "External redirects not allowed");
            return;
        }
        
        // For relative paths, validate against the allowlist
        String normalizedPath = uri.getPath();
        if (normalizedPath == null || !SAFE_REDIRECTS.contains(normalizedPath)) {
            // Default to safe fallback if path is not in allowlist
            response.sendRedirect("/home");
            return;
        }
        
        // Redirect only to allowlisted destinations
        response.sendRedirect(normalizedPath);
        return;
    }
}
```

## Explanation

The fix eliminates the open redirect vulnerability by implementing strict allowlist validation. The key changes are: (1) creating a server-defined set of trusted redirect destinations (`SAFE_REDIRECTS`), (2) rejecting any URL with a non-null host (indicating an attempt to redirect to an external domain, including scheme-relative URLs like `//evil.example`), and (3) validating relative paths against the allowlist before redirecting. Untrusted input no longer controls navigation targets. If a redirect destination is not in the allowlist, the application falls back to a safe default (`/home`) instead of rejecting the user's request.

## Behaviour changes

- Added `SAFE_REDIRECTS` constant to define server-controlled destinations
- Added validation to reject external domain redirects by checking `uri.getHost()`
- Changed redirect logic to select from allowlist instead of using user input directly
- Redirect now defaults to `/home` if the requested destination is not allowlisted (instead of sending the redirect as-is)
- Application now sends a `400 Bad Request` error for attempts to redirect to external domains, which is a new response not in the original code
