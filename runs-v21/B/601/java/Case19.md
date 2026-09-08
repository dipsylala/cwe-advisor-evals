## Verdict

**CWE-601: URL Redirection to Untrusted Site (Open Redirect)**

Confirmed exploitable. The code accepts user-controlled input and passes it directly to `response.sendRedirect()` without validating that the destination is a trusted domain. An attacker can craft a malicious link from a trusted domain that redirects victims to an attacker-controlled site, enabling phishing, credential theft, and other attacks.

## Source

**Call chain:**
- Case19A.handle() receives untrusted data and passes it to Case19B.handleSink()
- Case19B.handleSink() receives the untrusted `data` parameter
- The code validates that `data` is a syntactically valid URI (line 23) using `URI.create(data)`
- However, it does not validate that the URI refers to a trusted destination
- Line 32: `response.sendRedirect(data)` passes the untrusted URL directly to the redirect sink

**Vulnerability:** The URI syntax check only validates format, not trustworthiness. An attacker can pass malicious URLs like:
- `http://evil.com/phishing` (absolute URL)
- `//evil.com/phishing` (scheme-relative URL)
- These will be accepted by the syntax check and trigger an external redirect

## Fix

### File: Case19B.java

```java


package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import java.net.URI;
import java.net.URISyntaxException;

public class Case19B
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
            
            // Reject redirects to external domains - only allow relative paths
            if (uri.getHost() != null) {
                response.getWriter().write("Redirect to external domain not allowed");
                return;
            }
            
            response.sendRedirect(data);
            return;
        }

    }
}
```

## Explanation

The fix adds a host validation check after parsing the URI. The core protection uses `uri.getHost()` to detect whether the parsed URI refers to an external host:

- **Relative paths** (e.g., `/dashboard`, `./page.html`) have `getHost() == null` and are allowed—they cannot redirect outside the application
- **Absolute URLs** (e.g., `http://evil.com`) have a non-null host and are rejected
- **Scheme-relative URLs** (e.g., `//evil.com`) are NOT absolute per the URI spec (they have no scheme), but have a non-null host and are rejected—the guidance specifically highlights this case as a common bypass of naive `isAbsolute()` checks

The fix follows the guidance principle: "Reject redirects to external domains by default." By rejecting any URI with a host, only relative (context-local) redirects are allowed, eliminating the attack vector. If the application must support external redirects in the future, they can be added via an explicit allowlist check against `uri.getHost()`, but the default-deny posture closes the vulnerability now.

## Behaviour changes

- **Breaking change**: Redirects to absolute or external URLs are now rejected. Any call site that depends on redirecting to external domains will need to be updated to use context-relative paths or implement an allowlist.
- **New output**: When a redirect URL contains a host, the response writes "Redirect to external domain not allowed" instead of redirecting (previously would have redirected).
- **Same output for valid inputs**: Redirect to relative paths behaves identically—the URI is still passed to `sendRedirect()` as before.
