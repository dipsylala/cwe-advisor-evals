## Verdict

Exploitable. CWE-601 (URL Redirection to Untrusted Site), confidence: high.

## Source

`Case11A.handle()` reads a line of body content from `new URL("http://www.example.org/").openConnection().getInputStream()` (line 33) into `data`. This is data returned by an external network peer, not something the application originates or controls - `data` is untrusted from this point on regardless of the fact that the request URL itself is hardcoded. `data` is passed unchanged through `Case11B.handleSink()` -> `Case11C.handleSink()` -> `Case11D.handleSink()`, with no validation or transformation at any hop.

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

            // Only a same-origin relative path (no scheme, no host) is a permitted
            // redirect target; anything else - an absolute URL, a protocol-relative
            // URL (//evil.example), or an opaque scheme (javascript:, data:) - is rejected.
            if (uri.getHost() != null || uri.isAbsolute())
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

## Explanation

The sink at `Case11D.java` line 32 (`response.sendRedirect(data)`) passed the network-sourced, untrusted `data` value straight to the client's browser as a redirect target, letting an attacker who controls or manipulates the response of the fetched URL steer victims to an arbitrary site. The existing code already parsed the value with `new URI(data)` but only used the parse to catch syntactically malformed input, never to check where the URI actually points. The fix adds one check on the already-parsed `URI`: reject the value whenever it carries a host (`uri.getHost() != null`, which also catches protocol-relative values like `//evil.example` that a naive `startsWith("/")` check would miss) or is itself absolute with no host (`uri.isAbsolute()`, which catches opaque schemes such as `javascript:` or `data:`). Only a same-origin relative path passes through to `sendRedirect()`. No application-defined list of legitimate external redirect destinations exists anywhere in this call chain, so per the loaded guidance's default of rejecting external redirects rather than inventing an allowlist, the fix restricts redirects to relative paths instead of fabricating a set of trusted hosts.

## Behaviour changes

- Added validation before the sink: any redirect target with a host component, or any absolute URI with no host, is now rejected with the same `"Invalid redirect URL"` response body and early return already used by the adjacent `URISyntaxException` branch - this is a deliberate behavior change, not a side effect: absolute/external redirects that previously succeeded unconditionally will now fail closed. Relative-path redirects continue to work exactly as before.
- No other files, arguments, return values, or control flow were changed. `Case11A.java`, `Case11B.java`, and `Case11C.java` are unmodified; the fix is contained entirely in the sink file.
- Library recommendation: none - the fix uses only `java.net.URI`, already imported in the original file.

Verification: compiled the fixed `Case11D.java` with `javac 26` against stub `javax.servlet.http.HttpServletRequest`/`HttpServletResponse` and an empty `testcasesupport` package (matching the signatures the original file already relied on) in an isolated scratch directory. Compilation succeeded with no errors or warnings. Every symbol the fix adds (`uri.getHost()`, `uri.isAbsolute()`) is a pre-existing method on `java.net.URI`, already imported in the original file, so no new import was needed.
