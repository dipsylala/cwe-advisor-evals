## Verdict

Fixed. The vulnerability stems from passing untrusted redirect URLs to `response.sendRedirect()` without validating the parsed URI's host and scheme components.

## Source

Case11A reads data from an external URL via URLConnection.
The data flows through Case11B → Case11C → Case11D.
Case11D.handleSink() receives the untrusted data parameter and passes it directly to response.sendRedirect() on line 32.

## Fix

The fix validates the parsed URI to reject external domains and dangerous schemes:
- Reject any URI with a non-null host (catches both absolute URLs to external domains and scheme-relative URLs like `//evil.example`)
- Reject absolute URIs with null host (catches dangerous schemes like `javascript:` and `data:`)
- Allow only relative paths (no scheme, no host)

The URI is already parsed on line 23 (catching URISyntaxException), but the original code ignores the result. The fix uses the parsed URI to validate before calling sendRedirect().

### File: Case11D.java

```java

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import java.net.URI;
import java.net.URISyntaxException;

public class Case11D
{
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
            
            // Validate the redirect URL against safe patterns
            // Reject any URL with a non-null host (external domain or scheme-relative)
            if (uri.getHost() != null)
            {
                response.getWriter().write("Redirect to external domains is not allowed");
                return;
            }
            
            // Reject absolute URIs with null host (e.g., javascript: or data: schemes)
            if (uri.isAbsolute() && uri.getHost() == null)
            {
                response.getWriter().write("Invalid redirect URL");
                return;
            }
            
            // Only relative paths are allowed (no scheme, no host)
            response.sendRedirect(data);
            return;
        }

    }
}
```

## Explanation

The original code attempted to validate the URL by catching URISyntaxException when parsing it, but never checked the parsed URI's structure. This allowed attackers to supply URLs with external hosts (like `https://attacker.com`) or dangerous schemes (like `javascript:alert(1)`).

The fix adds validation after successful URI parsing:

1. **Check for external hosts**: `uri.getHost() != null` detects both absolute URLs (`https://evil.com`, which has host `evil.com`) and scheme-relative URLs (`//evil.example`, which has host `evil.example` but no scheme). This catches the bypass mentioned in the guidance where a `startsWith("/")` check would incorrectly allow scheme-relative URLs.

2. **Check for opaque/dangerous schemes**: `uri.isAbsolute() && uri.getHost() == null` rejects absolute URIs without a host component, which are dangerous schemes like `javascript:alert(1)` (which is absolute but has no host). This uses the distinction recommended in the guidance that differentiates between `isAbsolute()` and `getHost()`.

3. **Allow only relative paths**: If neither validation fails, the URL must be a relative path (no scheme, no host), which is safe to redirect to.

The fix preserves the existing behavior of passing the original untrusted string to `sendRedirect()` (not creating a new URL), which is correct because sendRedirect() handles encoding properly. The validation determines whether to allow the redirect, not what to send.

## Behaviour changes

- **Redirects to external domains are now rejected**: Any URL with an identifiable host (including scheme-relative URLs like `//evil.example`) is rejected.
- **Dangerous schemes are rejected**: URLs like `javascript:alert(1)` and `data:text/html,...` are rejected.
- **Relative paths are still allowed**: Paths like `/dashboard`, `../error`, `page.html` continue to work.
- **Error responses on rejection**: When validation fails, the response sends a plain-text error message instead of performing the redirect.
