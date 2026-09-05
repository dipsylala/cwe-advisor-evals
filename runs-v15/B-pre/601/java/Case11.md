## Verdict

Exploitable

## Source

Case11A reads untrusted data from `http://www.example.org/` (line 38) via `BufferedReader.readLine()`. The string is passed through Case11B and Case11C to Case11D without validation.

## Fix

**Vulnerable code:**
```java
// Line 32 in Case11D.java
response.sendRedirect(data);
```

**Fixed code:**
```java
// Implement an allowlist of safe redirect destinations
private static final Set<String> ALLOWED_REDIRECTS = new java.util.HashSet<>(
    java.util.Arrays.asList("/dashboard", "/home", "/profile")
);

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
        
        // Validate redirect target: reject external URLs, only allow relative paths in allowlist
        if (uri.getHost() != null)
        {
            // Reject any URL with an external host
            response.getWriter().write("External redirect not allowed");
            return;
        }
        
        // For relative paths (no host), verify against allowlist
        String path = uri.getPath();
        if (path == null || !ALLOWED_REDIRECTS.contains(path))
        {
            response.getWriter().write("Redirect not allowed");
            return;
        }
        
        // Use the validated path from allowlist for redirect
        response.sendRedirect(path);
        return;
    }
}
```

## Explanation

The fix validates the redirect destination before calling `sendRedirect()`. It uses the `URI.getHost()` check to reject any URL pointing to an external domain (the key distinction in the Java guidance: checking for a non-null host catches scheme-relative URLs like `//evil.com` that `isAbsolute()` would miss). For relative paths, the code validates against an allowlist of trusted destinations (`/dashboard`, `/home`, `/profile`) and rejects any path not explicitly approved. The fixed code uses the canonical value from the allowlist (not the original user input) when calling `sendRedirect()`, preventing attackers from redirecting users to arbitrary external sites via data sourced from untrusted remote URLs.

## Behaviour changes

- **Error handling**: Added explicit rejection of external redirect URLs with error message, whereas original code would accept them. This is a security improvement, not a regression.
- **Allowlist requirement**: Redirect destinations must now match the predefined allowlist. This constrains the application's redirect flexibility but is necessary to close the vulnerability.
- **No return value change**: The method still returns `void` as before, and error paths already return early in the original code.
