## Verdict

Confirmed. `Case10B.handleSink` passes an externally-sourced string directly to `HttpServletResponse.sendRedirect()` with no validation of the destination, allowing an open redirect to an attacker-controlled host.

## Source

`Case10A.handle()` reads the first line of the HTTP response body from a network connection (`urlConnection.getInputStream()`) into `data`. That content originates outside the application's trust boundary (whatever the remote server or a man-in-the-middle returns) and is passed unmodified into `Case10B.handleSink(data, request, response)`.

## Fix

### File: Case10B.java

```java

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import java.net.URI;
import java.net.URISyntaxException;

public class Case10B
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

            // The redirect target originates outside this application's trust boundary, so it
            // must not be handed to sendRedirect as-is: that would let the remote content pick
            // any absolute URL, including an attacker-controlled host (CWE-601 open redirect).
            // Only accept a same-application relative path: it must have no scheme and no
            // authority (so "http://evil.example/" and protocol-relative "//evil.example/" are
            // both rejected), and it must start with a single "/" and not "//" or "/\", which
            // browsers can still interpret as a scheme-relative host.
            String path = uri.getRawPath();
            boolean isSafeRelativePath = uri.getScheme() == null
                    && uri.getRawAuthority() == null
                    && path != null
                    && path.startsWith("/")
                    && !path.startsWith("//")
                    && !path.startsWith("/\\");

            if (!isSafeRelativePath)
            {
                response.getWriter().write("Invalid redirect URL");
                return;
            }

            response.sendRedirect(data);
            return;
        }

    }
}
```

## Explanation

`new URI(data)` only checks syntactic well-formedness; it does not restrict `data` to a same-site destination, so the original code let the externally-sourced value redirect a victim to any absolute URL. The fix inspects the parsed `URI` rather than pattern-matching the raw string: it requires no scheme and no authority component (rejecting `http://evil.example/`, `https://evil.example/`, and any other absolute form), and it requires the path to start with a single `/`, excluding both `//` and `/\` prefixes, which some browsers still resolve as a scheme-relative host (`//evil.example/...`) even though `URI` parses them as a path. Only a same-application relative path reaches `sendRedirect`; anything else is rejected with the same "Invalid redirect URL" response already used for a malformed URI, so behavior for legitimate same-site redirects (the case this handler exists to serve) is unchanged while every cross-host target is blocked.
