## Verdict

exploitable

## Source

Untrusted data enters in `Case10A.handle()` (`Case10A.java` lines 27-38). The servlet opens a cleartext connection to `http://www.example.org/` with `new URL(...).openConnection()`, wraps the stream in a `BufferedReader`, and assigns the first line of the remote response body to `data`. The value is whatever that remote endpoint - or anyone able to intercept an unauthenticated plaintext HTTP response - chooses to return; nothing in the application constrains it.

Path to the sink:

1. `Case10A.java:38` - `data = readerBuffered.readLine();` - the remote response body's first line becomes `data`.
2. `Case10A.java:73` - `(new Case10B()).handleSink(data, request, response);` - `data` is passed unchanged into the second class.
3. `Case10B.java:17` - `if (data != null)` - a null guard only; it does not constrain the value's content.
4. `Case10B.java:23` - `uri = new URI(data);` - the value is parsed, but the resulting `URI` is discarded. The parse is a syntax check only: it rejects malformed strings such as `/\evil.example`, but accepts `https://evil.example/`, `//evil.example`, and `javascript:alert(1)`.
5. `Case10B.java:32` - `response.sendRedirect(data);` - the original tainted string, not the parsed and validated value, is written into the `Location` header of a 302 response.

The break in the chain that would make this safe is a scheme/host decision taken on the parsed URI. There is none, so a first response line of `https://evil.example/login` makes the application emit a redirect from its own trusted origin to an attacker-controlled site - the classic phishing and credential-harvesting primitive. The path is exploitable as reported.

Sink contract at line 32, which the fix has to preserve: `sendRedirect(String)` returns void and commits a 302 with a `Location` header, resolving a relative argument against the current request URI; the single-argument form is the servlet default (302, buffer cleared) and nothing else is passed; it throws `IOException` if the response is already committed; the method returns immediately afterwards and the caller in `Case10A` does nothing with the outcome. The existing rejection path - write `"Invalid redirect URL"` to the response writer and return - is the file's established failure behaviour and is reused rather than replaced.

## Fix

No library or dependency change is required; the fix uses only `java.net.URI` and `java.util` from the JDK. `Case10A.java` is unchanged.

Vulnerable code (`Case10B.java`):

```java
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

            // The parsed URI is never inspected: scheme and host are unconstrained,
            // and the original tainted string - not the parsed value - reaches the sink.
            response.sendRedirect(data);
            return;
```

Complete fixed `Case10B.java`:

```java


package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import java.net.URI;
import java.net.URISyntaxException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class Case10B
{
    /* Server-defined redirect destinations. The key is the permitted host; the value is the
       canonical origin used to rebuild the target, so the scheme and host that reach the
       browser come from this map rather than from the untrusted value. Add an entry here for
       each external destination the application is genuinely allowed to redirect to. */
    private static final Map<String, String> ALLOWED_REDIRECT_ORIGINS;
    static
    {
        Map<String, String> origins = new HashMap<String, String>();
        origins.put("www.example.org", "https://www.example.org");
        ALLOWED_REDIRECT_ORIGINS = Collections.unmodifiableMap(origins);
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

            String target = resolveRedirectTarget(uri);
            if (target == null)
            {
                response.getWriter().write("Invalid redirect URL");
                return;
            }

            response.sendRedirect(target);
            return;
        }

    }

    /*
     * Returns a redirect target built from server-controlled values, or null if the supplied
     * URI is not a permitted destination. Decisions are taken on the parsed URI rather than on
     * the string, so a protocol-relative value such as "//evil.example" is seen as an authority
     * with no scheme and rejected instead of passing a "starts with /" test.
     */
    private String resolveRedirectTarget(URI uri)
    {
        if (uri.getScheme() == null && uri.getAuthority() == null)
        {
            /* Same-application relative reference. Require a rooted path so the target cannot
               be reinterpreted against the current request path. */
            String path = uri.getRawPath();
            if (path == null || !path.startsWith("/"))
            {
                return null;
            }
            return path + suffixOf(uri);
        }

        String scheme = uri.getScheme();
        String host = uri.getHost();
        if (host == null || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme)))
        {
            /* Rejects javascript:, data:, mailto: and any authority form that java.net.URI
               cannot resolve to a registered host name. */
            return null;
        }

        String origin = ALLOWED_REDIRECT_ORIGINS.get(host.toLowerCase(Locale.ROOT));
        if (origin == null)
        {
            return null;
        }

        String path = uri.getRawPath();
        if (path == null || path.length() == 0)
        {
            path = "/";
        }
        else if (!path.startsWith("/"))
        {
            return null;
        }

        /* The canonical origin from the allowlist is used, not the scheme, userinfo, host or
           port taken from the untrusted value. */
        return origin + path + suffixOf(uri);
    }

    private String suffixOf(URI uri)
    {
        StringBuilder suffix = new StringBuilder();
        if (uri.getRawQuery() != null)
        {
            suffix.append("?").append(uri.getRawQuery());
        }
        if (uri.getRawFragment() != null)
        {
            suffix.append("#").append(uri.getRawFragment());
        }
        return suffix.toString();
    }
}
```

The validator was exercised against the following inputs, which behave as intended: `/dashboard` and `/dashboard?a=1#f` are accepted unchanged; `""`, `dashboard`, `//evil.example`, `//evil.example/x`, `https://evil.example/`, `https://www.example.org.evil.com/`, `https://www.example.org@evil.com/` and `javascript:alert(1)` are all rejected; `/\evil.example` and `https://evil.com\@www.example.org/` are rejected earlier by the existing `URISyntaxException` branch; `http://www.example.org/news?q=1`, `HTTPS://WWW.EXAMPLE.ORG/x` and `https://user@www.example.org/p` resolve to targets rebuilt on the canonical `https://www.example.org` origin.

## Explanation

The parsed `URI` was previously computed and thrown away, so the only thing standing between the remote response body and the `Location` header was a syntax check, and the string handed to `sendRedirect` was the untrusted one. The fix takes the decision on the parsed value - scheme and authority, not string prefixes - and then, on success, rebuilds the redirect target from server-controlled data instead of forwarding the original input: a reference with no scheme and no authority is emitted as its own rooted path, and an absolute `http`/`https` URI is emitted only when its host appears in `ALLOWED_REDIRECT_ORIGINS`, in which case the scheme, host and port come from the map's canonical origin rather than from the attacker-supplied string. That closes the weakness on both axes a `startsWith("/")` style guard leaves open: `//evil.example` is an authority with no scheme and is rejected rather than treated as a path, and a host that merely resembles an allowed one (`www.example.org.evil.com`, `www.example.org@evil.com`) fails the exact map lookup because `URI.getHost()` returns the real registered host. Anything matching neither shape falls through to the file's existing rejection behaviour - write `"Invalid redirect URL"` and return - so failure handling stays consistent with the code that was already there.

## Behaviour changes

- **Redirects to hosts other than the allowlisted one now fail instead of succeeding.** This is the weakness being closed, not incidental. Rejections take the pre-existing failure branch, writing `"Invalid redirect URL"` and returning without a redirect, so the response shape on rejection matches what the file already did for an unparseable value. The map is seeded with `www.example.org`, the only destination the surrounding code demonstrably interacts with; deployments with other legitimate external destinations must add them.
- **Absolute allowlisted URLs are rebuilt on the canonical origin, so `http://www.example.org/x` now redirects to `https://www.example.org/x`.** This is required by the fix, not cosmetic: reusing the scheme and host parsed out of the untrusted value would put attacker-influenced text back into the `Location` header. The consequence is that a non-canonical scheme or port for an allowlisted host (`https://www.example.org:8443/x` becomes `https://www.example.org/x`) and any userinfo component are dropped. If a non-default port is legitimate, encode it in the map value.
- **A relative reference without a leading slash, and an empty string, are now rejected rather than resolved against the current request URI.** `sendRedirect` previously resolved `dashboard` or `""` relative to the request path; the validator requires a rooted path so that no target is decided by the request context. This matters for the observed failure mode in the caller: if the `URLConnection` read in `Case10A` throws `IOException`, `data` remains `""`, which used to produce a redirect back to the current URL and now produces the `"Invalid redirect URL"` response instead.
- **Path, query and fragment are otherwise preserved** for both the relative and the allowlisted-absolute case, using the raw (already percent-encoded) forms so the fix neither double-encodes nor decodes the value.
- **The sink contract is otherwise intact.** `sendRedirect` is still called in single-argument form with the servlet default status and buffer handling, still returns void, still commits the response, still propagates `IOException` on an already-committed response, and the method still returns immediately after. The `data != null` guard is unchanged, so a `null` first line from `readLine()` still results in no response being written. Nothing the original discarded is now surfaced, and no new output is produced on the success path.
- **Assumption recorded, resolved without asking:** the application has no configured list of permitted redirect destinations, so the allowlist was seeded with `www.example.org` - the host the caller already contacts - and the canonical origin was set to `https` in preference to the cleartext scheme the caller uses. This is the one part of the fix needing human confirmation against the deployment's real set of destinations; the validation logic itself does not depend on the map's contents. Confidence in the trace and in the rest of the fix is high.
