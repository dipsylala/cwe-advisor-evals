# CWE-601 Case11 Remediation

## Verdict

Exploitable. The vulnerable code at line 32 of Case11D.java calls `response.sendRedirect(data)` with a string that is parsed into a URI but the original unparsed string is passed to the sink. While `URISyntaxException` is caught to reject malformed URLs, the validation does not check whether the parsed URI points to an external domain or uses a dangerous scheme like `javascript:` or `data:`. This allows attackers to craft URLs that redirect users to arbitrary sites or trigger client-side code execution.

## Source

Case11A reads a string from a hardcoded URL (http://www.example.org/) via HTTP connection and stores the first line in variable `data`. This data flows through Case11B → Case11C → Case11D, where it reaches the sink.

The data originates as external content (`data = readerBuffered.readLine()` in Case11A:38) and is untrusted because it comes from an external HTTP source, not from a validated allowlist or application configuration.

## Fix

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

            // Validate redirect destination using the parsed URI
            String host = uri.getHost();
            String scheme = uri.getScheme();

            // Reject opaque URIs with dangerous schemes
            if (scheme != null && (scheme.equals("javascript") || scheme.equals("data")))
            {
                response.getWriter().write("Invalid redirect URL");
                return;
            }

            // Reject any redirect with a host component (external redirects not allowed)
            // Only allow relative paths (host will be null for relative URIs)
            if (host != null)
            {
                response.getWriter().write("Invalid redirect URL");
                return;
            }

            // Safe to redirect to relative path
            response.sendRedirect(data);
            return;
        }

    }
}
```

## Explanation

The fix uses the URI object that was already being parsed (but ignored) to validate the redirect destination. It checks two critical properties of the parsed URI:

1. **Scheme validation**: Rejects dangerous schemes like `javascript:` and `data:` that can execute code on the client side. This prevents attackers from crafting URLs like `javascript:alert(1)` or `data:text/html,<script>...`.

2. **Host validation**: Rejects any URI with a non-null host component, which indicates an external domain. This is the key fix—the original code parsed the URI but never checked whether it pointed to an external site. By calling `uri.getHost()` and rejecting when it returns non-null, the code now enforces that only relative paths (same-server redirects) are allowed. Relative paths have a null host, while absolute URIs like `https://attacker.com` or scheme-relative URLs like `//attacker.com` will have a non-null host.

This follows the CWE-601/Java guidance which states: "Decide on the parsed URI, not the string, but branch on `getHost()`, not `isAbsolute()`" because scheme-relative values like `//evil.example` have no scheme but still have a non-null host.

The validation rejects unsafe URLs and fails open by returning an error message rather than proceeding with an unsafe redirect.

## Behaviour changes

**Added validation checks**: Two additional conditional branches (lines 32-35 and 38-42) validate the parsed URI's scheme and host before calling `sendRedirect()`. These branches did not exist in the original code.

**Error message output**: The original code would silently proceed to `sendRedirect()` for any syntactically valid URI. The fixed code now writes "Invalid redirect URL" to the response writer when validation fails (in addition to the existing `URISyntaxException` handler).

**Rejection of external redirects**: A redirect to any URL with a host component (external domains) will now be rejected. This is a behavior change—the original code would have accepted such URLs.

**Rejection of dangerous schemes**: URLs with `javascript:` or `data:` schemes are now explicitly rejected. The original code would have accepted these.

**Constraint on redirect destinations**: Only relative paths (same-server URLs without a host component) are now permitted. This is a significant restriction from the original behavior where any syntactically valid URI would have been accepted. This is justified because the guidance requires either an allowlist of trusted destinations or relative paths only for safety; relative-path-only is the safest default for untrusted input.
