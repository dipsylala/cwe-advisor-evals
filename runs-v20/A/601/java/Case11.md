## Verdict

Confirmed. `Case11D.handleSink` passes externally-sourced data straight into `HttpServletResponse.sendRedirect(String)`. The value is never checked against any set of destinations the application controls, so a caller who influences it can redirect victims to an arbitrary site (phishing, credential harvesting, or bypassing a URL-based trust check downstream). Parsing the value into a `URI` only rejects malformed syntax; it does nothing to establish that the destination is one the application intends to send users to.

## Source

`Case11A.handle` opens a `URLConnection` to `http://www.example.org/` and reads the first line of the response body into `data` with `readerBuffered.readLine()`. That line is untrusted: it comes from a remote server's response content, not from a value the application itself constructed, so it must be treated as attacker-influenceable. `data` is then passed unchanged through `Case11B.handleSink` and `Case11C.handleSink` to the sink in `Case11D.handleSink`.

## Fix

### File: Case11D.java

```java

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class Case11D
{
    private static final Set<String> ALLOWED_REDIRECT_HOSTS =
        new HashSet<String>(Arrays.asList("www.example.org", "example.org"));

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

            if (!isAllowedRedirectTarget(uri))
            {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write("Invalid redirect URL");
                return;
            }

            // SAST FINDING: CWE-601 (URL Redirection to Untrusted Site) reported here. Sink is the next statement.
            response.sendRedirect(data);
            return;
        }

    }

    /**
     * A redirect target is acceptable only when it is a same-application relative
     * reference (no scheme and no host, so the browser resolves it against the
     * current origin) or when it explicitly names one of the destinations this
     * application is prepared to send users to. Anything else - including a
     * protocol-relative URL such as "//evil.example" - is rejected, because the
     * browser would resolve that to an attacker-controlled host.
     */
    private boolean isAllowedRedirectTarget(URI uri)
    {
        if (uri.isOpaque())
        {
            return false;
        }

        String host = uri.getHost();
        if (host == null)
        {
            // No host and not opaque: a plain relative reference (path, query,
            // and/or fragment only, no "//authority" section at all). Safe to
            // resolve against the current page's own origin.
            return uri.getRawAuthority() == null;
        }

        for (String allowedHost : ALLOWED_REDIRECT_HOSTS)
        {
            if (allowedHost.equalsIgnoreCase(host))
            {
                return true;
            }
        }

        return false;
    }
}
```

## Explanation

The sink itself, `response.sendRedirect(data)`, is unchanged - `sendRedirect` is the correct API for this and does not need replacing. What was missing is a check that the destination is one the application actually intends before that call runs.

`isAllowedRedirectTarget` accepts two cases only: a relative reference with no authority component (so the browser resolves it against the current page's own origin, which cannot be redirected off-site), and an absolute URL whose host exactly matches an explicit allowlist (`www.example.org`/`example.org`, the destination this data flow already originates from). Everything else - a different absolute host, a scheme-relative URL like `//evil.example/path` (which parses with a null `getHost()` in some JDK URI behaviors but carries a non-null authority string), or an opaque URI such as `mailto:` or `javascript:` - is rejected with a 400 response instead of being redirected to.

`uri.isOpaque()` is checked first because an opaque URI (no `/` after the scheme, e.g. `mailto:`, `javascript:`, or a bare `http:evil.example` with no `//`) has no host/authority structure to evaluate at all and must not fall through to the relative-reference branch, where a null host would otherwise read as "safe, relative." Verified against this JDK (`java.net.URI`, OpenJDK 26): a scheme-relative reference such as `//evil.example/path` parses with `isOpaque()==false` and `getHost()=="evil.example"`, so it is caught by the ordinary host-allowlist comparison, not treated as relative; a userinfo trick such as `http://www.example.org@evil.example/x` also resolves `getHost()` to the real target host (`evil.example`), not the userinfo segment, so it is rejected too. A host comparison is case-insensitive (`HTTP://WWW.EXAMPLE.ORG/x` still matches the allowlist), matching how DNS names are compared.

A denylist or a regex over the string form of `data` was deliberately avoided: string-based blocking is bypassable through case variation, extra slashes, or embedded credentials/userinfo, whereas parsing into a `URI` and inspecting its structured `host` field is not. This does not change behavior for any legitimate same-site relative redirect or a redirect back to `www.example.org`; it only removes the ability to redirect to an arbitrary third-party host.
