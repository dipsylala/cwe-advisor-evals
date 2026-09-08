## Verdict

Confirmed. `Case12E.handleSink` redirects the browser to a URL taken from external, untrusted content without validating the destination, allowing an attacker who controls that content to send users to an arbitrary site (open redirect).

## Source

`Case12A.handle` opens a connection to `http://www.example.org/` and reads the first line of the response body into `data`:

```
data = readerBuffered.readLine();
```

That value is treated as untrusted (it originates outside the application, from a remote server's response body, not from a literal the developer controls) and is passed unmodified through `Case12B.handleSink` -> `Case12C.handleSink` -> `Case12D.handleSink` into `Case12E.handleSink`.

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

            // Only allow a same-application, relative redirect target: no scheme
            // (rules out "http://evil.com"), no authority component (rules out
            // protocol-relative "//evil.com", which a browser resolves against an
            // arbitrary host), and a path that is rooted at the application ("/...").
            String path = uri.getPath();
            boolean isSafeRelativeTarget = !uri.isAbsolute()
                    && uri.getAuthority() == null
                    && path != null
                    && path.startsWith("/");

            if (!isSafeRelativeTarget)
            {
                response.getWriter().write("Invalid redirect URL");
                return;
            }

            String target = uri.getRawPath();
            if (uri.getRawQuery() != null)
            {
                target = target + "?" + uri.getRawQuery();
            }

            response.sendRedirect(target);
            return;
        }

    }
}
```

## Explanation

The original code parsed `data` as a `URI` only to catch malformed syntax, then redirected to it regardless of what it pointed to - an absolute URL such as `http://attacker.example/phish` or a protocol-relative `//attacker.example` passes `URI` parsing just as easily as an in-app path, so the syntax check gave no protection against redirection to an untrusted site.

The fix keeps the existing parse-and-catch structure but adds the missing check: it only allows redirect targets that are relative references rooted at the application (`uri.isAbsolute()` false, `uri.getAuthority()` null, and a path starting with `/`). This rejects any target carrying a scheme or host - including protocol-relative `//host` links, which have no scheme but do have an authority - while still allowing legitimate same-app redirects like `/account/dashboard?tab=billing`. Anything else (an absolute URL, a scheme-relative URL, or a malformed value) returns the existing "Invalid redirect URL" response instead of redirecting. The redirect is reconstructed from `uri.getRawPath()` and `uri.getRawQuery()` rather than the raw `data` string so the value that reaches `sendRedirect` is exactly what was validated.

This does not require an allowlist of external domains because the application does not need to redirect to any domain other than itself; constraining the target to a relative, rooted path is the narrowest fix that preserves the feature (redirecting the client to another location) while eliminating the open-redirect condition.
