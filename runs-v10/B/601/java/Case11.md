## Verdict

Confirmed: CWE-601 (URL Redirection to Untrusted Site). The code parses user-supplied input as a URI and immediately redirects to it without validating the destination. A syntactically valid but untrusted URL (e.g., `https://attacker.com`) will be redirected to, enabling phishing and credential theft.

## Source

The vulnerability originates at the `data` parameter of `handleSink()`, which flows from Case11A (reading from a network source) through Case11B and Case11C as pass-throughs, and reaches the vulnerable sink in Case11D.

Data flow chain:
- Case11A: Reads `data` from network (`http://www.example.org/`)
- Case11B: Passes `data` through to Case11C
- Case11C: Passes `data` through to Case11D
- Case11D line 32: `response.sendRedirect(data)` – untrusted URL reaches the sink without destination validation

## Fix

Replace the `handleSink()` method in Case11D.java to validate the redirect destination against an allowlist:

```java
package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Set;

public class Case11D
{
    // Allowlist of trusted redirect destinations (hosts)
    private static final Set<String> TRUSTED_HOSTS = new HashSet<>();
    
    static {
        TRUSTED_HOSTS.add("www.example.org");
        TRUSTED_HOSTS.add("example.org");
    }
    
    // Allowlist of trusted relative redirect paths
    private static final Set<String> TRUSTED_RELATIVE_PATHS = new HashSet<>();
    
    static {
        TRUSTED_RELATIVE_PATHS.add("/");
        TRUSTED_RELATIVE_PATHS.add("/dashboard");
        TRUSTED_RELATIVE_PATHS.add("/home");
    }
    
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
            
            // Validate redirect destination before redirecting
            if (!isValidRedirectDestination(uri))
            {
                response.getWriter().write("Redirect to this URL is not allowed");
                return;
            }
            
            response.sendRedirect(data);
            return;
        }
    }
    
    private boolean isValidRedirectDestination(URI uri)
    {
        String host = uri.getHost();
        
        // Check for scheme-relative URLs (//evil.com) or absolute URLs with host
        if (host != null)
        {
            // Absolute or scheme-relative URL – validate host against allowlist
            String scheme = uri.getScheme();
            
            // Reject opaque schemes like javascript: or data:
            if (scheme == null || "javascript".equalsIgnoreCase(scheme) || "data".equalsIgnoreCase(scheme))
            {
                return false;
            }
            
            // Only allow http and https schemes
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))
            {
                return false;
            }
            
            // Check if host is in the allowlist
            return TRUSTED_HOSTS.contains(host);
        }
        
        // No host – check if it's a relative path
        String path = uri.getPath();
        if (path != null && TRUSTED_RELATIVE_PATHS.contains(path))
        {
            return true;
        }
        
        // Reject all other cases
        return false;
    }
}
```

## Explanation

The fix introduces destination validation before invoking `response.sendRedirect()`. The key changes are:

1. **Allowlist validation**: Two allowlists are maintained – `TRUSTED_HOSTS` for absolute URLs and `TRUSTED_RELATIVE_PATHS` for relative redirects.

2. **URI component checking**: Following the CWE-601 Java guidance, the fix uses `uri.getHost()` rather than `isAbsolute()` to detect absolute and scheme-relative URLs. A scheme-relative URL like `//evil.com` has no scheme but has a non-null host, so it is correctly classified as requiring host validation.

3. **Scheme validation**: The fix explicitly rejects dangerous schemes (`javascript:`, `data:`) and only permits `http` and `https`.

4. **Relative path validation**: URLs with no host are treated as relative paths and validated against a whitelist of safe paths.

5. **Default rejection**: Any URL that does not match the allowlist is rejected with a user-facing error message before the redirect is issued.

This closes CWE-601 by ensuring that only server-defined, allowlisted destinations can be redirected to, preventing attackers from using the application as an open redirect to phishing sites.

## Behaviour changes

- **Redirects to untrusted hosts rejected**: Any `response.sendRedirect()` call with a host not in `TRUSTED_HOSTS` now fails and returns an error message instead of redirecting.
- **Dangerous schemes blocked**: URLs using `javascript:` or `data:` schemes are rejected outright.
- **Relative paths constrained**: Relative redirects are accepted only if they match entries in `TRUSTED_RELATIVE_PATHS`.
- **Error message on failure**: Invalid redirect attempts return a 200 response with an error message rather than a redirect, preventing silent failures and alerting developers to attacks.
- **No change to valid redirects**: Redirects to allowlisted hosts with valid schemes continue to work as before.
