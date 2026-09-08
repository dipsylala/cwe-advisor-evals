## Verdict

exploitable

## Source

`Case10A.handle()` opens a `URLConnection` to a remote host and reads the first line of the response body (`readerBuffered.readLine()`) into `data`. This is externally-sourced network data, not something the application originates or controls the content of. `data` is passed unchanged into `(new Case10B()).handleSink(data, request, response)`.

## Fix

### File: Case10B.java

```java

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class Case10B
{
    private static final Set<String> ALLOWED_REDIRECT_HOSTS =
        new HashSet<>(Arrays.asList("www.example.org"));

    private static final String SAFE_DEFAULT_REDIRECT = "/";

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

            // Resolve to a trusted, canonical redirect target instead of
            // forwarding the untrusted string straight to the sink.
            String target = resolveSafeRedirectTarget(uri);
            response.sendRedirect(target);
            return;
        }

    }

    private static String resolveSafeRedirectTarget(URI uri)
    {
        String host = uri.getHost();

        if (host == null)
        {
            // No authority component: only accept a same-app relative path.
            // Reject scheme-relative ("//evil.example") and opaque
            // (e.g. "javascript:...") values, which report a null path here.
            String path = uri.getPath();
            if (path != null && path.startsWith("/") && !path.startsWith("//"))
            {
                return uri.toString();
            }
            return SAFE_DEFAULT_REDIRECT;
        }

        if (ALLOWED_REDIRECT_HOSTS.contains(host))
        {
            return uri.toString();
        }

        return SAFE_DEFAULT_REDIRECT;
    }
}
```

## Explanation

`handleSink()` previously only checked that `data` parsed as a syntactically valid `URI` before handing it straight to `response.sendRedirect(data)` - a well-formed URI to any attacker-controlled host still passed. The fix parses the URI once (unchanged) and then classifies it: a value with a non-null `getHost()` is only accepted if it exactly matches an entry in a fixed allowlist (`ALLOWED_REDIRECT_HOSTS`); a value with a null host is only accepted if it is a same-app relative path (`getPath()` starts with a single `/`, not `//`, which rejects the protocol-relative `//evil.example` bypass and opaque schemes like `javascript:` whose `getPath()` is null). Anything that fails both checks falls back to a fixed safe path (`"/"`) rather than being passed through. The resolved, trusted `target` string - never the original `data` - is what reaches `sendRedirect()`, per the allowlist-fix-point requirement of using the canonical value downstream, not the tainted one.

## Behaviour changes

- Redirects to hosts other than `www.example.org` (the only destination the sample application is shown to use) now go to `/` instead of the attacker-controlled URL. This is the intended effect of closing the open redirect and is not a regression.
- Relative-path redirects (`data` with no host, e.g. `/dashboard`) continue to work exactly as before, since they satisfy the same-path check.
- The existing malformed-URI branch (`catch (URISyntaxException)` writing "Invalid redirect URL") is unchanged.
- No signature, argument, or return-type changes to `handleSink()`; `Case10A.java` is untouched.

**Assumption:** the allowlist is seeded with `www.example.org`, the only host this call chain is shown contacting (in `Case10A`, as the source of `data` itself, not as a shown redirect destination). No application configuration or set of legitimate redirect destinations was available in the case files, so this is a placeholder the real allowlist should replace with the application's actual approved redirect targets; confidence on the specific allowlist membership is therefore medium, though the mechanism (host allowlist + relative-path check, safe-path fallback) is high confidence per the loaded CWE-601 Java guidance.

**Verification:** compiled the fixed `Case10B.java` with `javac` (JDK 26) against minimal stand-in stubs for `javax.servlet.http.HttpServletRequest`/`HttpServletResponse` and an empty `testcasesupport` package (the real servlet-api and test-support jars are outside the reviewed scope) in a scratch directory. Compilation succeeded with zero errors or warnings.
