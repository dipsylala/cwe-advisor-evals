## Verdict

Exploitable. Confidence: medium.

- **cwe_id**: CWE-601 (URL Redirection to Untrusted Site / Open Redirect)
- **location**: `Case10B.java`, line 32 (`response.sendRedirect(data)`)

## Source

`Case10A.handle()` opens a `URLConnection` and reads the first line of the response body (`readerBuffered.readLine()`) into `data`. That value is passed unchanged into `Case10B.handleSink(data, request, response)`, which parses it as a `URI` (rejecting only syntactically invalid values) and then redirects the client to it with no destination validation.

**Assumption**: the connection target is a literal `http://www.example.org/` in this file, but the pattern stands in for any externally-sourced response body (a remote call, a webhook payload, an upstream service) whose content the application does not control. The line it reads is treated as attacker-influenceable data for this trace, consistent with how the language guidance's Taint Sinks section treats `response.sendRedirect()` as a sink regardless of how the tainted string reached it. Confidence is lowered to medium for this reason - the exploitability depends on whether the remote endpoint's response can, in practice, be influenced by an attacker.

## Fix

Library recommendation: none - no third-party library is required, this is a first-party allowlist check using `java.net.URI`, already imported in the file.

Vulnerable code (`Case10B.java`):

```java
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
```

Fixed code:

```java
import java.util.Locale;
import java.util.Set;

public class Case10B
{
    // Placeholder allowlist - populate with this application's actual trusted redirect hosts.
    private static final Set<String> ALLOWED_REDIRECT_HOSTS = Set.of("www.example.org");

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
            if (host != null)
            {
                // Absolute or scheme-relative (//evil.example) target: only allow a listed host.
                if (!ALLOWED_REDIRECT_HOSTS.contains(host.toLowerCase(Locale.ROOT)))
                {
                    response.getWriter().write("Invalid redirect URL");
                    return;
                }
            }
            else if (uri.isAbsolute())
            {
                // Absolute with no host (e.g. javascript:, data:) - reject rather than fall through as safe.
                response.getWriter().write("Invalid redirect URL");
                return;
            }
            // Otherwise: relative path with no host - stays on this application, safe to redirect to.

            response.sendRedirect(data);
            return;
        }
    }
}
```

(Only the added imports, the new field, and the inserted validation block are new; the rest of the file, including the `AbstractTestCaseServlet` call site in `Case10A.java`, is unchanged.)

## Explanation

The sink parsed the untrusted string into a `URI` only to reject malformed syntax, then redirected to it regardless of destination - a syntactically valid `https://attacker.example/` or protocol-relative `//attacker.example` passed through unchecked. The fix branches on `uri.getHost()` rather than `uri.isAbsolute()`, per the language guidance: a non-null host (covering both `https://attacker.example` and the browser-treated-as-absolute `//attacker.example`) is checked against a server-side allowlist, and an absolute URI with a null host (an opaque scheme such as `javascript:`) is rejected outright instead of being allowed to fall through. A relative path (`host == null` and not absolute) is left untouched, since it necessarily stays within this application. `ALLOWED_REDIRECT_HOSTS` is a placeholder seeded with the one host visible in this trace; it needs to be replaced with the application's actual set of legitimate redirect targets before this ships.

## Behaviour changes

- A redirect value whose host is not in `ALLOWED_REDIRECT_HOSTS` (or that is an absolute opaque URI with no host) now gets the same `"Invalid redirect URL"` response and early return that the code already used for a syntactically invalid URI, instead of being redirected to. This is the intended effect of the fix, not a side effect.
- No change to the success path: an allowlisted or relative destination still reaches `response.sendRedirect(data)` with the same argument, same return type (`void`), and the same declared failure behaviour (`IOException` via `throws Throwable`).
- No change to `Case10A.java` or the call site `(new Case10B()).handleSink(data, request, response)` - the fix is contained to `Case10B.handleSink()`.
