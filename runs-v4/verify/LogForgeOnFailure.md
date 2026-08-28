# CWE-117 - LogForgeOnFailure.java:25

## Verdict

**Exploitable.** Confidence: high.

`username` is read straight from an HTTP request parameter and concatenated into a log message with no encoding anywhere between the two. The reported line sits in the `catch (AuthenticationException e)` block, which is the branch an attacker reaches most easily - any request with a bad password lands there - so the sink is not on a rare error path but on the default path for unauthenticated traffic.

A value such as `alice\nINFO  Login succeeded for admin` (with a real newline, or a carriage return) makes the log file contain a second, fully-formed-looking line that the application never emitted. Because the forged line lands in the same file the authentication audit trail lives in, it can hide a brute-force run, frame another account, or poison whatever aggregator ingests the file. Carriage returns, ANSI escape sequences (`ESC`, 0x1B), NUL bytes and the Unicode separators U+0085/U+2028/U+2029 give the same or related effects depending on what parses the file downstream.

## Source

| | |
|---|---|
| Source | `LogForgeOnFailure.java:14` - `request.getParameter("user")` |
| Sink (reported) | `LogForgeOnFailure.java:25` - `logger.error("Login failed for " + username, e)` |
| Second sink (same weakness) | `LogForgeOnFailure.java:19` - `logger.info("Login succeeded for {}", username)` |

**Path.** `request.getParameter("user")` assigns to `username` at line 14. `username` is passed unchanged to `authenticator.authenticate(...)` at line 18 and, in the same scope, into both logging calls. There is no validation, canonicalisation, length limit or encoding step between line 14 and either sink - `username` reaches them byte-for-byte as it arrived on the wire.

**Why line 25 is the reported one.** The message is built by `+` concatenation, so the untrusted value is already fused into the message string before SLF4J is called. No encoding stage exists at any layer: the appender receives one opaque string and has no way to tell the literal prefix from the attacker's bytes.

**Line 19 is the same weakness, one step less obvious.** The `{}` placeholder keeps the template and the value separate, but separation is not neutralisation - under a conventional pattern layout the substituted value is still written raw, and a newline inside it forges an entry exactly as it does on line 25. Fixing only the reported line would leave the finding live on the success path.

**Existing contract at line 25**, which the fix has to preserve:

- **Returns** - `void`; no caller consumes a result.
- **Discards** - nothing.
- **Implicit arguments** - the call binds the `error(String, Throwable)` overload, so `e` is logged as a throwable and the appender renders its stack trace. That must survive the change; demoting `e` to an ordinary format argument would silently drop the stack trace.
- **Failure behaviour** - SLF4J logging does not throw. Control always reaches `response.setStatus(SC_UNAUTHORIZED)` on the next line, and the HTTP response must not become dependent on the logging call succeeding.

## Fix

### Vulnerable code

```java
String username = request.getParameter("user");

try
{
    authenticator.authenticate(username, request.getParameter("password"));
    // Parameterized, but the value is still substituted raw into the output line.
    logger.info("Login succeeded for {}", username);
    response.setStatus(HttpServletResponse.SC_OK);
}
catch (AuthenticationException e)
{
    // Untrusted request parameter concatenated into the message: nothing downstream
    // can distinguish the literal prefix from attacker-supplied control characters.
    logger.error("Login failed for " + username, e);
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
}
```

### Fixed code

```java
package evalcases;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LogForgeOnFailure
{
    private static final Logger logger = LoggerFactory.getLogger(LogForgeOnFailure.class);

    public void handle(HttpServletRequest request, HttpServletResponse response, Authenticator authenticator)
    {
        String username = request.getParameter("user");
        String safeUsername = encodeForLog(username);

        try
        {
            authenticator.authenticate(username, request.getParameter("password"));
            logger.info("Login succeeded for {}", safeUsername);
            response.setStatus(HttpServletResponse.SC_OK);
        }
        catch (AuthenticationException e)
        {
            logger.error("Login failed for {}", safeUsername, e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    /**
     * Renders a value safe to write into a log line: every character that can
     * terminate a line, move the cursor, or be mistaken for an escape is replaced
     * by its own printable Unicode escape form (backslash-u plus four hex digits).
     * Characters are escaped, never dropped, so an injection attempt stays visible
     * in the audit trail instead of disappearing.
     */
    private static String encodeForLog(String value)
    {
        if (value == null)
        {
            return "null";
        }

        StringBuilder encoded = new StringBuilder(value.length());

        for (int i = 0; i < value.length(); i++)
        {
            char c = value.charAt(i);

            // 0x00-0x1F: ASCII controls, including CR, LF and ESC (ANSI colour sequences).
            // 0x7F-0x9F: DEL and the C1 controls, which covers NEL (U+0085).
            // U+2028/U+2029: Unicode line and paragraph separators.
            // The backslash itself: without it, the two typed characters \ and n would
            // render identically to a real encoded newline and a reader could not tell
            // which one actually arrived.
            if (c == '\\' || c <= 0x1F || (c >= 0x7F && c <= 0x9F) || c == 0x2028 || c == 0x2029)
            {
                encoded.append(String.format("\\u%04X", (int) c));
            }
            else
            {
                encoded.append(c);
            }
        }

        return encoded.toString();
    }
}
```

`encodeForLog` is shown as a private helper to keep the change self-contained. In a codebase that logs untrusted values in more than one class, move it to a shared logging utility and call it from every such site rather than copying it.

### Library note

No dependency change is required to close this finding, and none should be attempted as part of it. The durable follow-up is to move the application to structured JSON logging, where the encoder escapes control characters inside field boundaries as a property of the format rather than by a call at each site - `logstash-logback-encoder` for a Logback binding, or `log4j-layout-template-json` for Log4j2, configured in `logback.xml` or `log4j2.xml`.

Treat that as separate work. It depends on which binding is actually on the classpath, it reformats every line the application emits, and its version has to come from advisory or SCA data rather than being assumed - resolve it with dependency-check tooling before merging. The call-site encoding above is what closes this line, and it holds whatever the logging configuration turns out to be.

### Verifying

Submit `user` values containing a literal CR and LF, a NUL byte, `ESC[31m`, a raw U+2028, and the two-character sequence backslash-n, then confirm each appears in the log as a `\uXXXX` escape on a single line, that the five cases remain distinguishable from one another, and that the failed-login stack trace is still present.

## Explanation

The fix encodes the untrusted value at the call site and replaces the concatenation with a parameterized call, which are two halves of one change rather than alternatives. `encodeForLog` converts every character that could terminate a log line or drive a terminal - the ASCII control range, DEL and the C1 controls (which include NEL, U+0085), the Unicode separators U+2028 and U+2029, and the backslash itself - into a visible `\uXXXX` escape, so an attacker's newline can no longer close the record and open a forged one; escaping the backslash is what keeps a typed backslash-n distinguishable from an encoded real newline, and escaping rather than stripping keeps the injection attempt itself in the audit trail, which is precisely what an incident responder needs to see. Switching line 25 from `"Login failed for " + username` to the `{}` placeholder keeps the template and the value separate so the sink can act on them independently; on its own it neutralises nothing, which is why the encoding accompanies it rather than being replaced by it, and it is also why line 19 - already parameterized but still emitting the raw value - is fixed in the same pass. The encoded value is bound to a new `safeUsername` variable so that only the logging calls see it: `authenticator.authenticate` continues to receive the original `username`, since encoding the credential being checked would change who can log in.

## Behaviour changes

- **The reported sink now binds `error(String, Object, Throwable)` instead of `error(String, Throwable)`.** SLF4J treats a trailing `Throwable` that has no matching `{}` placeholder as the exception argument, so `e` is still logged as a throwable and its stack trace still rendered. Reason: required to move from concatenation to a placeholder while keeping the sink contract intact.
- **Logged usernames containing control characters now render as `\uXXXX` escapes, and a literal backslash renders as `\u005C`.** This is the weakness closing, but it is an output-format change: any log parser, alerting rule, or dashboard that matches on usernames should be checked for regex or exact-match rules that assumed a raw value. Normal usernames - letters, digits, dots, hyphens, `@` - pass through byte-for-byte and are unaffected.
- **Line 19, the success path, was changed as well as the reported line 25.** It logs the same untrusted value and, being parameterized but unencoded, was forgeable in the same way; fixing only the reported line would have left the finding live. Reason: same weakness, same source, one call away.
- **`String safeUsername` is computed once at line 15, on every request rather than only on the logging paths.** Reason: both sinks need it, and a single encoded variable prevents a later edit from logging the raw `username` by mistake. The original value is still what reaches `authenticator.authenticate`, so authentication behaviour is unchanged.
- **A null `user` parameter still logs as `null`.** `request.getParameter` returns `null` when the parameter is absent; the original concatenation rendered that as the text `null`, and the SLF4J placeholder would too, so `encodeForLog` returns `"null"` to preserve it. No `NullPointerException` is introduced on the missing-parameter path.
- **No change to HTTP status codes, control flow, exception handling, or the authentication call.** `SC_OK` and `SC_UNAUTHORIZED` are set exactly as before, and no new exception can escape `handle`.
- **No dependency, manifest, or logging-configuration change is required**, so nothing here alters the format of any other line the application emits.

### Assumptions

- The `Authenticator` and `AuthenticationException` types are not present in the file under review; they are treated as an opaque authentication collaborator whose contract the fix does not touch. The fix does not depend on their behaviour.
- The logging configuration is not visible from this file, so a conventional pattern layout writing to a line-oriented file or console is assumed. The call-site encoding is chosen precisely because it holds under any layout, including a structured one; under a JSON encoder it becomes redundant for the ASCII control range but remains correct and still covers the separators that several JSON encoders emit raw.

> Unblinded verification run, not a scored result. See RESULTS-v4.md for the run this fix came from.
