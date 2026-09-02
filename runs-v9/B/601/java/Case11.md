## Verdict

- **CWE-601** - URL Redirection to Untrusted Site ('Open Redirect')
- **Location**: `Case11D.java`, `handleSink()`, line 32 (`response.sendRedirect(data)`)
- **Verdict**: exploitable
- **Confidence**: high
- **Assumptions**: The concrete host allowlist below is illustrative - this is a synthetic four-file test fixture with no real application routes to draw a legitimate destination list from. `www.example.org` is kept as the one example entry (it is already the host this code fetches from) so the pattern is visible; a developer applying this fix must replace it with their application's actual approved redirect destinations.

## Source

- **Origin**: `Case11A.handle()` opens a `URLConnection` to a hardcoded URL (`http://www.example.org/`) and reads the first line of the response body via `BufferedReader.readLine()` into `data` (lines 27-38). This is data from an external network resource outside the application's control - not sanitized or validated at any point in the chain.
- **Path**: `data` is returned from the try/finally block in `Case11A.handle()` and passed unchanged through `Case11B.handleSink(data, request, response)` -> `Case11C.handleSink(data, request, response)` -> `Case11D.handleSink(data, request, response)`. None of the three intermediate hops (`Case11A`, `Case11B`, `Case11C`) inspect, transform, or constrain the value.
- **Sink**: In `Case11D.handleSink()`, `data` is parsed with `new URI(data)` (line 23), but the only check performed is whether construction throws `URISyntaxException` - a syntax check, not a trust check. Any syntactically valid URI, including an absolute URL to an attacker-controlled host, a scheme-relative value (`//evil.example`), or an opaque scheme (`javascript:...`), reaches `response.sendRedirect(data)` at line 32 unchanged.

## Fix

No third-party library is required; this is a code-level fix using `java.net.URI`, already imported in `Case11D.java`.

**Vulnerable code** (`Case11D.java`):

```java
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

            // SAST FINDING: CWE-601 (URL Redirection to Untrusted Site) reported here. Sink is the next statement.
            response.sendRedirect(data);
            return;
        }

    }
}
```

**Fixed code** (`Case11D.java`):

```java
package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Set;

public class Case11D
{
    // Placeholder allowlist - replace with the application's actual approved
    // redirect destinations.
    private static final Set<String> ALLOWED_REDIRECT_HOSTS = Set.of("www.example.org");
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

            String host = uri.getHost();

            if (host == null && !uri.isAbsolute())
            {
                // Relative path (no scheme, no host) - stays within this application.
                response.sendRedirect(data);
                return;
            }

            if (host != null && ALLOWED_REDIRECT_HOSTS.contains(host.toLowerCase(Locale.ROOT)))
            {
                // Absolute URL to an allowlisted host.
                response.sendRedirect(data);
                return;
            }

            // Untrusted destination: external host, scheme-relative ("//evil.example"),
            // or an opaque/absolute scheme with no host (e.g. "javascript:..."). Fall
            // back to a fixed, safe destination rather than the attacker-influenced value.
            response.sendRedirect(DEFAULT_SAFE_REDIRECT);
            return;
        }

    }
}
```

## Explanation

The original code treated a successful `new URI(data)` parse as sufficient proof the redirect target was safe, but syntactic validity says nothing about trust - it happily accepts `https://attacker.example/phish`, `//evil.example` (browser-interpreted as protocol-relative), and opaque schemes. The fix adds an actual trust decision on the parsed `URI`, per the language guidance: a value with no host and no scheme (`uri.getHost() == null && !uri.isAbsolute()`) is a same-application relative path and is safe to redirect to directly; a value with a non-null host is only redirected to when that host is present in a server-side allowlist; everything else - including scheme-relative values (non-null host, so it fails the relative-path branch) and opaque/no-host absolute URIs like `javascript:` (which fails the allowlist branch since `host` is null) - falls through to a fixed, safe default path instead of being forwarded to the browser. The pre-existing `URISyntaxException` handling, which already rejects malformed input including unencoded-backslash values, is left untouched. This closes the open-redirect weakness because the untrusted network-sourced string can no longer determine an external navigation target; it can, at most, select between "allowed" and "fall back to a fixed safe path."

## Behaviour changes

- **Redirect destination on validation failure**: previously any syntactically valid URI was redirected to verbatim; now a URI whose host is absent-but-scheme-bearing, non-allowlisted, or scheme-relative is redirected to `DEFAULT_SAFE_REDIRECT` ("/") instead. This is the security fix itself - the whole point is to stop forwarding the untrusted value - not incidental scope creep.
- **New allowlist dependency**: introduces `ALLOWED_REDIRECT_HOSTS`, a static, server-controlled set, and two new imports (`java.util.Set`, `java.util.Locale`) to support it. This is the mechanism the fix requires and carries the assumption noted in Verdict: the single placeholder entry must be replaced with the application's real approved destinations before this is production-ready.
- **Everything else unchanged**: the `data != null` guard, the `URISyntaxException` catch and its "Invalid redirect URL" response, the method signature, and the relative-path happy path all behave exactly as before. `response.sendRedirect()`'s own return/throw contract (`void`, `IOException` on I/O failure or `IllegalStateException` if the response is already committed) is unaffected for both the allowed and fallback branches.
