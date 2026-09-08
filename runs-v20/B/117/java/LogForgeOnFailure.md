## Verdict

exploitable

- **cwe_id**: CWE-117 (Improper Output Neutralization for Logs)
- **location**: `LogForgeOnFailure.java`, line 25 (reported sink); line 19 shares the same source and is fixed alongside it
- **confidence**: high

## Source

`request.getParameter("user")` (line 14) - an HTTP request parameter, fully attacker-controlled. It is assigned to `username` and reaches two logging sinks in the same method with no validation or encoding in between:

- Line 19 (success path): `logger.info("Login succeeded for {}", username)` - uses an SLF4J `{}` placeholder, which keeps the template separate from the value but does not encode it.
- Line 25 (reported failure path): `logger.error("Login failed for " + username, e)` - builds the message by string concatenation, so `username` lands directly in the log text.

An attacker who submits a `user` value containing a raw newline (or a backslash followed by `n`, which reads identically once written) can inject a fabricated log line - e.g. forging a bogus `"Login succeeded for admin"` entry into the audit trail, or hiding the real failed attempt among synthetic lines.

**Sink contract (both call sites):**
- **Returns**: `void`; the caller does not use a return value.
- **Discards**: nothing beyond the message text itself.
- **Arguments left implicit**: line 25 passes the `AuthenticationException e` as the trailing argument to `logger.error(String, Object...)`; SLF4J's varargs formatter detects a `Throwable` in the final slot that has no matching `{}` placeholder and logs it as the exception (with stack trace) rather than treating it as a substitution value. This existing behavior must be preserved.
- **Failure behaviour**: neither call throws under normal use; logging failures are handled internally by the SLF4J binding and are out of scope for this fix.

## Fix

### File: LogForgeOnFailure.java

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

        try
        {
            authenticator.authenticate(username, request.getParameter("password"));
            logger.info("Login succeeded for {}", sanitizeForLog(username));
            response.setStatus(HttpServletResponse.SC_OK);
        }
        catch (AuthenticationException e)
        {
            logger.error("Login failed for {}", sanitizeForLog(username), e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    /**
     * Escapes characters that would let attacker-controlled input forge or split log
     * entries: the full ASCII control range (0x00-0x1F), DEL (0x7F), the Unicode line/
     * paragraph separators (U+0085, U+2028, U+2029), and the backslash itself (so an
     * escaped sequence cannot be confused with a real control character).
     */
    private static String sanitizeForLog(String value)
    {
        if (value == null)
        {
            return "null";
        }

        StringBuilder sanitized = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++)
        {
            char c = value.charAt(i);
            if (c == '\\')
            {
                sanitized.append("\\\\");
            }
            else if (c <= 0x1F || c == 0x7F || c == 0x0085 || c == 0x2028 || c == 0x2029)
            {
                sanitized.append(String.format("\\u%04x", (int) c));
            }
            else
            {
                sanitized.append(c);
            }
        }
        return sanitized.toString();
    }
}
```

## Explanation

The fix adds a local `sanitizeForLog` helper that encodes, at the call site, exactly the characters the loaded CWE-117 Java guidance flags as forging vectors: the ASCII control range (0x00-0x1F), DEL (0x7F), the Unicode line/paragraph separators (U+0085, U+2028, U+2029), and the backslash itself (escaped first, and checked as its own branch, so a literal `\` in the input can never be misread as introducing one of the `\uXXXX` escapes the sanitizer emits). Untrusted characters are replaced with their `\uXXXX` representation rather than stripped, so the log retains evidence that an injection attempt occurred instead of silently deleting it. `null` is preserved as the literal string `"null"`, matching what string concatenation produced for the original code on an absent parameter, so behavior for a missing `user` value is unchanged.

Both sinks that carry the tainted `username` are fixed, not only the reported line: line 25 (the reported concatenation) and line 19 (the success path, which used an SLF4J `{}` placeholder that separates template from value but - per the loaded guidance - does not itself encode). Both are converted to call `sanitizeForLog(username)` and pass the result through `{}`. On the failure path, `sanitizeForLog(username)` and `e` are passed as two arguments to `logger.error(String, Object...)`; SLF4J's formatter finds one `{}` placeholder and a trailing `Throwable` with no matching placeholder, so it substitutes the sanitized username into the message and logs `e`'s stack trace exactly as `logger.error(msg, e)` did before - the exception's stack trace is not lost. No third-party library was introduced: the guidance's Apache Commons Text alternative (`StringEscapeUtils.escapeJava()`) does not encode DEL (0x7F), and this hand-rolled encoder is self-contained, so no new dependency or version needs to be tracked.

## Behaviour changes

- Both log lines now render `username` as its encoded form (control characters, DEL, the three Unicode separators, and backslashes rendered as `\uXXXX`/`\\`) instead of the raw value. Ordinary usernames (letters, digits, punctuation, non-ASCII text with no control characters) are emitted unchanged - only the characters listed in the CWE-117 guidance are affected. This is the intended effect of the fix, not incidental.
- A `null` `user` parameter now logs as the string `"null"` via the sanitizer's explicit null check, identical to what `"Login failed for " + null` produced under string concatenation - no behavior change here, called out because the sanitizer had to be given an explicit reason to preserve it.
- `logger.error` moves from the two-argument `(String, Throwable)` overload to the varargs `(String, Object...)` overload with a `{}` placeholder; per SLF4J's documented handling of a trailing `Throwable` argument with no corresponding placeholder, the exception is still logged with its full stack trace - no loss of diagnostic information.
- HTTP status codes returned on each path (`SC_OK`, `SC_UNAUTHORIZED`) and the authentication call itself are untouched.

**Verification**: The fixed file, together with minimal local stand-ins for `javax.servlet.http.HttpServletRequest`/`HttpServletResponse`, `org.slf4j.Logger`/`LoggerFactory`, and the file's own `Authenticator`/`AuthenticationException` types, was compiled with `javac` (JDK 26, `-encoding UTF-8`) in an isolated scratch directory. It compiled with no errors or warnings. `sanitizeForLog` was additionally traced by hand against SLF4J's documented varargs/Throwable handling to confirm the exception argument on line 25 is still logged with its stack trace rather than being consumed as a message-format argument.

**Assumptions**: The project's actual `pom.xml`/`build.gradle` was not part of the provided call chain, so no new third-party dependency was introduced for the sanitizer; this keeps the fix self-contained rather than assuming Apache Commons Text is already on the classpath. Line 19 was brought into scope alongside the reported line 25 per the CWE-117 guidance's instruction to fix every sink sharing the same tainted source in the file, not only the one the scanner reported.
