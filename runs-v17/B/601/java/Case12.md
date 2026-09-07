## Verdict

EXPLOITABLE - CWE-601 URL Redirection to Untrusted Site. The application accepts untrusted data from an external source and passes it through a chain of methods to `response.sendRedirect()` without validating that the destination is safe. An attacker can supply an arbitrary absolute URL (e.g., `https://attacker.com`) to redirect users to a malicious site.

## Source

Data flows from Case12A, which reads a line from `http://www.example.org/` and assigns it to the `data` variable. This data is external and attacker-controllable. The data is passed unchanged through Cases B, C, and D to Case12E, where it reaches the vulnerable sink.

## Fix

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
            
            // Reject absolute URLs with a non-null host (prevents redirects to external domains)
            if (uri.getHost() != null)
            {
                response.getWriter().write("Redirect to external sites not allowed");
                return;
            }
            
            // Reject dangerous schemes
            String scheme = uri.getScheme();
            if ("javascript".equals(scheme) || "data".equals(scheme))
            {
                response.getWriter().write("Invalid redirect URL");
                return;
            }
            
            // Only allow relative paths (starting with /)
            if (!data.startsWith("/"))
            {
                response.getWriter().write("Redirect must be to a relative path");
                return;
            }
            
            response.sendRedirect(data);
            return;
        }

    }
}
```

## Explanation

The fix closes CWE-601 by implementing strict validation of redirect destinations. The vulnerability existed because the code parsed the URI to check syntax validity but never validated whether the redirect target was safe before passing it to `sendRedirect()`.

The fix adds three layers of defense:

1. **Host validation**: Checks `uri.getHost() != null` to detect absolute URLs with external hosts. This rejects URLs like `https://attacker.com` or scheme-relative URLs like `//evil.com` which have a non-null host but no scheme. Per the Java guidance, branching on `getHost()` is more precise than using `isAbsolute()`, which misclassifies both cases.

2. **Dangerous scheme rejection**: Explicitly rejects `javascript:` and `data:` schemes to prevent JavaScript execution or data URL attacks.

3. **Relative path enforcement**: Restricts redirects to relative paths (those starting with `/`), allowing only in-application navigation. This prevents all external redirects by default.

Only data that passes all three checks reaches the sink. This ensures `sendRedirect()` receives only safe, relative paths that keep users within the application.

## Behaviour changes

- Absolute URLs (with a host component) are rejected with a 400-style response message instead of being redirected.
- Scheme-relative URLs (like `//evil.com`) are rejected because they have a non-null host.
- Dangerous schemes (`javascript:`, `data:`) are rejected.
- Non-relative paths (those not starting with `/`) are rejected.
- Only relative paths starting with `/` are accepted for redirection (e.g., `/dashboard`, `/logout`).
- The application now defaults to rejecting external redirects, which prevents phishing and credential theft attacks.
