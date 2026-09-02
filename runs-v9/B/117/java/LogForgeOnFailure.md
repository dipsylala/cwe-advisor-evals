## Verdict

CWE-117 (Improper Output Neutralization for Logs) - **exploitable**. Confidence: high.

`LogForgeOnFailure.handle()` reads `user` directly from the HTTP request and writes it into the log with no encoding. Nothing between the source and either logging call constrains its content: the value passes straight to `authenticator.authenticate()` (which does not transform or validate the string it was given for logging purposes) and then to the logger. An attacker can supply a `user` value containing `\r`, `\n`, or other control characters to forge additional log lines or corrupt the entry.

## Source

- **Source**: `request.getParameter("user")` - `LogForgeOnFailure.java:14`. Attacker-controlled HTTP parameter, assigned to `username`.
- **Reported sink**: `logger.error("Login failed for " + username, e)` - `LogForgeOnFailure.java:25`. Untrusted `username` is concatenated directly into the log message string.
- **Same-file, same-source sink not separately reported**: `logger.info("Login succeeded for {}", username)` - `LogForgeOnFailure.java:19`. This already uses an SLF4J `{}` placeholder, but a placeholder only keeps template and value separate - it does not encode the substituted value, so `username` still reaches the log unescaped on the success path.

## Fix

No third-party library is required; the loaded Java guidance treats call-site encoding as the change that closes a reported finding regardless of logging backend, and names `org.apache.commons.text.StringEscapeUtils.escapeJava()` only as an optional maintained alternative to hand-rolled escaping (and notes it still misses DEL 0x7F). Since no build manifest is available to confirm Commons Text is already a dependency, the fix below adds a small local encoder instead of introducing a new dependency for one finding.

Vulnerable code:

```java
catch (AuthenticationException e)
{
    // SAST FINDING: CWE-117 (Improper Output Neutralization for Logs) reported here. Sink is the next statement.
    logger.error("Login failed for " + username, e);
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
}
```

Fixed code:

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
        String safeUsername = sanitizeForLog(username);

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
     * Encodes a value before it is written to the log so it cannot forge or
     * split log entries. Escapes the ASCII control range (0x00-0x1F), DEL
     * (0x7F), the Unicode line separators U+0085/U+2028/U+2029, and the
     * backslash itself (so an attacker-supplied literal "\n" cannot become
     * indistinguishable from an escaped real newline).
     */
    private static String sanitizeForLog(String value)
    {
        if (value == null)
        {
            return "null";
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++)
        {
            char c = value.charAt(i);
            if (c == '\\')
            {
                sb.append("\\\\");
            }
            else if (c < 0x20 || c == 0x7F || c == '\u0085' || c == '\u2028' || c == '\u2029')
            {
                sb.append(String.format("\\u%04x", (int) c));
            }
            else
            {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
```

## Explanation

The fix adds a local `sanitizeForLog()` encoder and applies it to `username` before either logging call, replacing string concatenation at the reported sink (line 25) with an SLF4J `{}` placeholder plus the encoded value, and encoding the value at the pre-existing placeholder sink (line 19) as well, since a placeholder alone does not neutralize the substituted argument. Encoding, rather than stripping, escapes control characters, the Unicode line-separator characters, and the backslash itself into visible `\uXXXX` sequences, so an attacker cannot inject a real newline (or a literal backslash-n that would otherwise render identically to one) to forge additional log lines, while the original value's presence and intent remain visible in the log for incident response. The `Throwable e` is kept as the trailing argument to `logger.error`, which SLF4J recognizes as the exception to attach even when it follows a formatted argument, so the stack trace is still logged exactly as before.

## Behaviour changes

- `username` passed to `authenticator.authenticate()` is unchanged (still the raw value) - authentication behaviour is not affected, only what reaches the log.
- Log line 25 changes from message-concatenation form to SLF4J placeholder form (`"Login failed for {}", safeUsername, e`); the rendered text differs only when `username` contains control characters, a backslash, or a Unicode line separator, in which case those characters now appear as visible `\uXXXX` escapes instead of their raw (and exploitable) form.
- Log line 19 (not the reported sink, but the same untrusted source reaching a second logging call in the same file) is likewise changed to log the encoded value instead of the raw one, for the same reason.
- `response.setStatus()` calls, control flow, and exception handling are unchanged.
- No new dependency is introduced and no existing method signature is altered.
