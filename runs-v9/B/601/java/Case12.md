## Verdict

Exploitable. CWE-601 (URL Redirection to Untrusted Site), confidence: high.

## Source

`Case12A.handle()` (Case12A.java, lines 27-38) opens a `URLConnection` to `http://www.example.org/` (plain HTTP, no TLS) and reads the first line of the response body into `data`. That value is untrusted: it comes from an external, unauthenticated network response that an on-path attacker can alter (trivial over plain HTTP) or that the remote host itself can serve as attacker-influenced content. `data` is passed unmodified through `Case12B.handleSink()` -> `Case12C.handleSink()` -> `Case12D.handleSink()` (pure pass-through calls, no validation or transformation in any of them) into `Case12E.handleSink()`.

## Fix

Vulnerable code (`Case12E.java`, lines 12-37):

```java
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
            
            // SAST FINDING: CWE-601 (URL Redirection to Untrusted Site) reported here. Sink is the next statement.
            response.sendRedirect(data);
            return;
        }

    }
}
```

Fixed code:

```java
package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Set;

public class Case12E
{
    // No legitimate external redirect destination was identified anywhere in the
    // traced call chain, so this starts empty; add a host here only for a
    // confirmed, business-required external redirect target.
    private static final Set<String> ALLOWED_REDIRECT_HOSTS = Set.of();
    private static final String DEFAULT_SAFE_REDIRECT = "/";

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

            String redirectTarget;
            String host = uri.getHost();
            if (host == null && !uri.isAbsolute())
            {
                // No scheme, no authority: a relative path that stays inside this
                // application, safe to use as-is.
                redirectTarget = data;
            }
            else if (host != null && ALLOWED_REDIRECT_HOSTS.contains(host.toLowerCase(Locale.ROOT)))
            {
                // Absolute or scheme-relative URL to an explicitly allowlisted host.
                redirectTarget = data;
            }
            else
            {
                // Absolute/scheme-relative URL to a non-allowlisted host, or an
                // opaque absolute URI with no host (e.g. "javascript:...") - do not
                // honor an externally-sourced redirect target.
                redirectTarget = DEFAULT_SAFE_REDIRECT;
            }

            // SAST FINDING: CWE-601 (URL Redirection to Untrusted Site) - now redirects
            // only to a relative in-app path or an allowlisted host, never to the
            // untrusted value read from the remote response.
            response.sendRedirect(redirectTarget);
            return;
        }

    }
}
```

## Explanation

The original code validated only that `data` parses as a syntactically well-formed URI, then passed that same untrusted value straight to `response.sendRedirect()` - so any string returned by the remote `www.example.org` fetch (including an absolute URL to an attacker-controlled host, or a scheme-relative value like `//evil.example`) was honored as the redirect target. The fix inspects the already-parsed `URI` and branches on `getHost()` rather than `isAbsolute()`, per the language guidance: a value with no scheme and no host is a same-application relative path and is safe to use unchanged; a value with a host is only used if that host is on `ALLOWED_REDIRECT_HOSTS`; everything else - including an opaque absolute URI with a null host - falls back to a fixed, safe in-app path (`/`). This closes the open redirect while still allowing legitimate relative redirects to pass through and leaving a documented extension point (the allowlist) for any future, explicitly approved external destination.

## Behaviour changes

- When `data` is an absolute URL or scheme-relative value (host present) and that host is not in `ALLOWED_REDIRECT_HOSTS` (currently empty - no legitimate external destination was identified in the traced chain), the response now redirects to `/` instead of the attacker-influenced URL. This is the fix itself, not incidental.
- When `data` is an opaque absolute URI with no host (e.g. a `javascript:`/`data:`-style value that still parses as a valid `URI`), the response now redirects to `/` instead of passing that value to `sendRedirect()`. This is also the fix itself: the previous code would have forwarded it unchanged.
- Relative-path values (no scheme, no host) continue to be redirected exactly as before, since `URISyntaxException` handling, method signature, return type, and control flow are otherwise unchanged.
- Assumption: no legitimate external redirect target was evident anywhere in the traced call chain, so `ALLOWED_REDIRECT_HOSTS` is left empty and the safe fallback path is a generic `/`; a developer with knowledge of the real application should populate the allowlist (or pick a more specific fallback route) if an external or non-root destination is actually required.
