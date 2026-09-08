## Verdict

VULNERABLE. The code parses input as a URI to check syntactic validity but then sends an unvalidated redirect using the original string, allowing attackers to redirect users to arbitrary external domains.

## Source

The data flows from an external HTTP source read in Case12A line 38, passed through pass-through methods Case12B, Case12C, and Case12D, to Case12E.handleSink() where it reaches the sink at line 32.

## Fix

The vulnerability is in Case12E.java. The code validates URI syntax but does not validate the redirect destination. The fix restricts redirects to relative paths only by checking the parsed URI's host and scheme components.

### File: Case12E.java

```java


package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import java.net.URI;
import java.net.URISyntaxException;

public class Case12E
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
            
            // Reject absolute URLs pointing to external hosts
            if (uri.getHost() != null)
            {
                response.getWriter().write("External redirects not allowed");
                return;
            }
            
            // Reject opaque URIs (e.g., javascript:, data: schemes)
            if (uri.getScheme() != null && uri.getHost() == null)
            {
                response.getWriter().write("Invalid redirect URL");
                return;
            }
            
            // Only relative paths are safe to redirect to
            response.sendRedirect(data);
            return;
        }

    }
}
```

## Explanation

The fix adds two validation checks after parsing the URI:

1. **Host check**: If `uri.getHost()` returns non-null, the URL is an absolute URL pointing to an external host (including scheme-relative URLs like `//evil.example`). These are rejected.

2. **Opaque URI check**: If the URI has a scheme but no host (like `javascript:alert(1)` or `data:text/html`), it is rejected. This prevents dangerous handlers from being invoked.

Only relative URLs (those without a host and without an opaque scheme) are allowed to proceed to `sendRedirect()`. Relative URLs like `/dashboard`, `../path`, or `?param=value` are safe because they cannot redirect to external domains.

This approach matches the Java guidance requirement to "branch on `getHost()`, not `isAbsolute()`" and correctly handles edge cases like scheme-relative URLs that would bypass simple `isAbsolute()` checks.

## Behaviour changes

The fixed code rejects redirects to external domains and blocks opaque URI schemes. Legitimate redirect destinations must be relative paths (within the same origin). Applications requiring external redirects would need to implement an allowlist of approved external domains instead; this fix prioritizes the safer default of rejecting all external redirects.

