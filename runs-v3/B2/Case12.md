## Verdict

exploitable

## Source

Untrusted data enters in `Case12A.handle()` (`Case12A.java:27-38`): the servlet opens a
`URLConnection` to `http://www.example.org/` and assigns the first line of that remote HTTP
response body to `data` via `readerBuffered.readLine()`. The value is never validated, parsed for
scheme/host, or constrained after it is read.

Path to the sink, unchanged at every hop:

1. `Case12A.handle()` line 38 - `data = readerBuffered.readLine();` (remote response body)
2. `Case12A.handle()` line 73 - `new Case12B().handleSink(data, request, response)`
3. `Case12B.handleSink()` line 13 - forwards `data` to `Case12C`
4. `Case12C.handleSink()` line 13 - forwards `data` to `Case12D`
5. `Case12D.handleSink()` line 13 - forwards `data` to `Case12E`
6. `Case12E.handleSink()` line 32 - `response.sendRedirect(data)`

The only check on the path is the `null` guard at `Case12E.java:17` and the `new URI(data)`
construction at line 23. That construction is a syntax check only: its result is assigned to `uri`
and then discarded, and the raw `data` string is what reaches `sendRedirect`. A syntactically valid
absolute URI such as `https://attacker.example/login`, a protocol-relative value such as
`//attacker.example/login`, or a `javascript:`/`data:` scheme all parse successfully and are then
emitted verbatim in the `Location` header.

The retrieval is over cleartext `http://` with no TLS and no integrity check on the body, so the
redirect destination is controlled by whoever controls that remote host or any point on the network
path between the application and it. That is an off-application party in every case, which makes the
value untrusted input to a navigation sink.

## Fix

Complete fixed `Case12E.java`:

```java


package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import java.net.URI;
import java.net.URISyntaxException;

public class Case12E
{
    private static final String DEFAULT_REDIRECT = "/";

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

            response.sendRedirect(localRedirectTarget(uri));
            return;
        }

    }

    private static String localRedirectTarget(URI uri)
    {
        if (uri.getScheme() != null || uri.getAuthority() != null)
        {
            return DEFAULT_REDIRECT;
        }

        String path = uri.getRawPath();
        if (path == null || !path.startsWith("/") || path.startsWith("//"))
        {
            return DEFAULT_REDIRECT;
        }

        StringBuilder target = new StringBuilder(path);
        if (uri.getRawQuery() != null)
        {
            target.append('?').append(uri.getRawQuery());
        }
        if (uri.getRawFragment() != null)
        {
            target.append('#').append(uri.getRawFragment());
        }
        return target.toString();
    }
}
```

No library change is needed; the fix uses `java.net.URI`, which the file already imports.

If this deployment genuinely needs to redirect off-site, add a `Map` of allowed hosts to their
canonical `scheme://host` prefix, and in the absolute branch rebuild the target from the map's
canonical prefix plus the parsed path - never from the incoming string. Nothing in the current call
chain indicates an external destination is required, so the code above rejects all of them.

## Explanation

The redirect decision now runs on the parsed `URI` that the code was already building and throwing
away, and the value handed to `sendRedirect` is rebuilt from that parsed object instead of being the
original untrusted string. A target is accepted only when it carries no scheme and no authority and
its path begins with a single `/`, which is the shape of a same-application path; every other value
falls back to the fixed server-controlled path `/`. Rejecting on `getAuthority()` rather than on a
string prefix is what stops `//attacker.example/login`, which a browser reads as protocol-relative
and which a `startsWith("/")` test would wave through, and rejecting on `getScheme()` stops both
absolute `http`/`https` destinations and `javascript:`/`data:` values. Because the emitted string is
assembled from the URI's raw path, query, and fragment, the bytes that were validated are the bytes
that reach the `Location` header, so there is no gap between the checked form and the used form.
Attacker control of the remote response body can therefore no longer steer the victim's browser
anywhere outside the application.

## Behaviour changes

- **Non-local destinations now redirect to `/`.** Any `data` value that is absolute
  (`https://...`), protocol-relative (`//host/path`), scheme-bearing (`javascript:`, `data:`), or a
  relative path not starting with `/` produces a 302 to `/` instead of to the value. This is the
  weakness being closed, but it also affects a legitimate absolute URL pointing at the
  application's own host - that case now lands on `/` and needs an explicit host allowlist if it is
  required.
- **Empty or path-less values now redirect to `/`.** `data = ""` previously produced
  `sendRedirect("")`; it now produces a 302 to `/`. The response is still a redirect, so the caller
  sees no structural difference.
- **The redirect target is reassembled from the parsed URI's raw path, query, and fragment**
  rather than passed through as the original string. For an accepted local path the result is
  equivalent, with the exception that any part of the input the `URI` parser does not classify as
  path, query, or fragment is dropped. This is deliberate: the validated value has to be the value
  that is used.
- **The previously discarded `uri` is now read.** No new output, no new logging, and nothing
  previously suppressed is surfaced.
- **Unchanged:** the `data != null` guard and its silent no-op path; the `URISyntaxException`
  handler and its `"Invalid redirect URL"` response body; the single-argument `sendRedirect` call,
  so the status code stays 302 and the container still resolves the relative target against the
  request context; the `return` immediately after the redirect; the method signature and its
  `throws Throwable`. `Case12A` through `Case12D` are untouched.
- **Assumption recorded:** the response body read over cleartext `http://` from a third-party host
  is treated as attacker-influenceable input. If that endpoint were instead a trusted internal
  service reached over an authenticated channel, the finding's severity would drop, but the sink
  would still pass an unvalidated string to `sendRedirect` and the same fix would apply.
- **Confidence:** high. The call chain is direct and complete within the five files, every hop
  passes the value unmodified, and the sink contract (void return, 302, container-relative
  resolution, `IOException` on a committed response) is preserved.
