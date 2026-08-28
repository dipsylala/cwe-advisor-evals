# CWE-601 - Case11

- **CWE:** CWE-601 (URL Redirection to Untrusted Site)
- **Location:** `evals/cases-v2/Case11/Case11D.java:32`
- **Sink:** `response.sendRedirect(data)`
- **Confidence:** high

## Verdict

exploitable

## Source

Untrusted data enters in `Case11A.handle()`. The servlet opens a network connection with
`(new URL("http://www.example.org/")).openConnection()` and assigns `data =
readerBuffered.readLine()` (`Case11A.java:38`) - the first line of a remote HTTP response.
The value is chosen entirely by whoever controls that response: the remote host itself, anyone
able to tamper with the plaintext HTTP exchange, or anyone able to influence DNS for it. Nothing
in the application constrains its contents.

Path to the sink:

1. `Case11A.handle()` - `data = readerBuffered.readLine()` (source, line 38), then
   `(new Case11B()).handleSink(data, request, response)` (line 73).
2. `Case11B.handleSink()` - passes `data` through unchanged to
   `(new Case11C()).handleSink(...)` (line 13).
3. `Case11C.handleSink()` - passes `data` through unchanged to
   `(new Case11D()).handleSink(...)` (line 13).
4. `Case11D.handleSink()` - `new URI(data)` (line 23), then `response.sendRedirect(data)`
   (line 32, the sink).

No sanitiser sits on this path. The `new URI(data)` call at line 23 looks like a guard but is
not one: it checks RFC 3986 syntax only, and its result `uri` is discarded without a single
check being made against it. Every value an attacker would want here parses cleanly -
`http://evil.example/`, `https://evil.example/login`, `javascript:alert(1)` and
`//evil.example/x` all construct a valid `URI`, so the `catch` block never fires and the raw
string reaches `sendRedirect` unchanged. The parse rejects only malformed input, which is not
the property that matters for a redirect target.

Sink contract as it currently stands: `sendRedirect(String)` returns `void`, commits the
response with a 302 and a `Location` header, discards nothing, and is called in its
single-argument form (302 status and container-relative resolution are the defaults in play).
It throws `IOException` if the response is already committed. The caller does nothing with a
return value and simply `return`s afterwards. Any fix has to preserve all of that.

## Fix

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

            String path = uri.getRawPath();

            
            
            
            if (uri.isAbsolute() || uri.getRawAuthority() != null
                    || path == null || !path.startsWith("/") || path.startsWith("//"))
            {
                response.getWriter().write("Invalid redirect URL");
                return;
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

            response.sendRedirect(target.toString());
            return;
        }

    }
}
```

No new imports and no new dependency are required; `URI` and `URISyntaxException` are already
imported by the file.

## Explanation

The decision about where to send the user is now made on the parsed `URI` rather than on the
raw string, and the destination handed to `sendRedirect` is rebuilt from that parsed object
instead of being the attacker's text. Three conditions have to hold before a redirect happens:
the URI carries no scheme (`isAbsolute()` is false, which rejects `http://evil.example/` as
well as `javascript:` and `data:` payloads), it carries no authority (`getRawAuthority() ==
null`, which rejects the protocol-relative `//evil.example/x`), and its path is root-relative
(`startsWith("/")` but not `//`). That leaves only same-origin destinations, so no input can
name a host any more. Rebuilding the target from `getRawPath()`, `getRawQuery()` and
`getRawFragment()` rather than reusing `data` is load-bearing rather than cosmetic: `URI`
parses `///evil.example` to the harmless path `/evil.example` and `////evil.example` to
`//evil.example`, and forwarding the original string would leave a `Location` value that
browsers and intermediaries may re-normalise back toward the attacker's host. Emitting the
parsed path removes that ambiguity, and the explicit `//` test catches the one multi-slash
input whose parsed path is itself protocol-relative. Values that fail validation take the
error path the method already had - the same `"Invalid redirect URL"` message and `return` used
for a syntax failure - so no new response shape, status code or exception type is introduced.
No cross-host redirect requirement is visible anywhere in this call chain, so absolute URIs are
refused outright rather than measured against a host allowlist; if external destinations are
genuinely needed later, add an explicit allowlist of permitted hosts and redirect to the
canonical URL selected from that list rather than to the submitted value.

## Behaviour changes

- **Untrusted destinations are refused, and this is the weakness closing.** Absolute URIs
  (`http:`, `https:`, `javascript:`, `data:`), protocol-relative values (`//host`,
  `////host`), and references that are not root-relative are no longer redirect targets. They
  now take the pre-existing `"Invalid redirect URL"` writer path and `return`. The reused error
  path means the failure mode is one the method already produced.
- **The `sendRedirect` argument is rebuilt from the parsed URI instead of being `data`.**
  Required, not incidental: it is what defeats the `///evil.example` and `////evil.example`
  normalisation cases described above. For every value that passes validation the emitted
  string is otherwise identical to the original input - path, query and fragment are all
  preserved in their raw (already percent-encoded) form.
- **`uri` is now used rather than parsed and discarded.** The variable the original code
  computed at line 23 and abandoned is now the value the decision is made on. Nothing new
  escapes the method.
- **Reviewer-facing edge case:** the empty string and bare relative references such as
  `dashboard` were previously passed to `sendRedirect` and resolved against the current URL;
  they are rejected now. If any caller depends on current-URL-relative redirects, it must send
  a root-relative path (`/dashboard`) instead. This is the only input class whose legitimate
  use could be affected.
- **Unchanged:** the method signature, the `data != null` guard, the `URISyntaxException`
  handling and its message, the trailing `return`, the `void` return type, and the
  single-argument `sendRedirect` call - so the default 302 status and the container's
  relative-URL resolution both behave exactly as before. No argument was supplied where the
  original left a default, no output the original discarded is now surfaced, and no call order
  changed.
