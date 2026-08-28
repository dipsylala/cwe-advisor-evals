## Verdict

- **CWE:** CWE-117 (Improper Output Neutralization for Logs)
- **Location:** `e:/Github/cwe-advisor/evals/cases/117/java/LogForgeOnFailure/LogForgeOnFailure.java`, line 25
- **Verdict:** exploitable
- **Confidence:** high for the code-level sink; medium for the logging configuration half, which depends on an assumption recorded below
- **Assumptions:**
  - Logback is the SLF4J binding behind `org.slf4j.Logger`. Only the SLF4J API is visible in the single-file case, and Logback is the common pairing. If the binding is Log4j2 instead, the code change is identical and the configuration change becomes `log4j-layout-template-json` with a `JsonTemplateLayout` in `log4j2.xml`.
  - The application currently writes plain-text log lines, since no logging configuration accompanies the class.

## Source

Data flow, single frame, no intermediate transformation:

- **Source:** line 14, `String username = request.getParameter("user")` - the `user` query/form parameter, fully attacker-controlled, including CR, LF, and Unicode separators.
- **Propagation:** `username` is passed to `authenticator.authenticate(...)` at line 18 and is otherwise unmodified. Nothing validates, truncates, or encodes it. When authentication throws, control reaches the catch block with the tainted value intact - and the failure path is the one an attacker can trigger at will, by supplying any wrong password.
- **Sink:** line 25, `logger.error("Login failed for " + username, e)`. The username is concatenated into the message string, so any control characters it carries are written straight into the log record.

Sink contract as it stands:

- **Returns:** nothing; the caller ignores the call.
- **Discards:** nothing. The message and the `AuthenticationException` are both intended for the log.
- **Implicit arguments:** the two-argument `error(String, Throwable)` overload, so `e` is rendered as a stack trace rather than as a message parameter. Any replacement must keep the throwable in throwable position.
- **Failure behaviour:** does not throw and does not affect control flow; line 26 sets HTTP 401 regardless.

Second sink in the same method: line 19, `logger.info("Login succeeded for {}", username)`. It is already parameterized, so it needs no code change, but parameterization alone neutralizes nothing - it only keeps the value separate so the appender can encode it. Until the appender encodes, this line is forgeable in exactly the same way as line 25, and fixing only the reported line leaves the weakness live on the success path.

## Fix

**1. Dependency and logging configuration**

Add the structured-logging encoder. The version has to come from your SCA or advisory data - resolve it there before merging rather than pinning it from memory:

```xml
<dependency>
  <groupId>net.logstash.logback</groupId>
  <artifactId>logstash-logback-encoder</artifactId>
  <version><!-- resolve via SCA / dependency-check --></version>
</dependency>
```

Point the appender at the JSON encoder in `logback.xml`:

```xml
<configuration>
  <appender name="JSON" class="ch.qos.logback.core.ConsoleAppender">
    <encoder class="net.logstash.logback.encoder.LogstashEncoder"/>
  </appender>
  <root level="INFO">
    <appender-ref ref="JSON"/>
  </root>
</configuration>
```

Confirm every appender in the file routes through the JSON encoder - a plain-text file appender kept alongside the console one still writes forgeable lines. Confirm the layout emits one event per line and that nothing prepends a timestamp or level outside the JSON object.

**2. Vulnerable code**

```java
        catch (AuthenticationException e)
        {
            // CWE-117: username is concatenated into the message, so CR/LF in the
            // "user" parameter forges additional log lines.
            logger.error("Login failed for " + username, e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
```

**3. Fixed code**

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
            logger.info("Login succeeded for {}", username);
            response.setStatus(HttpServletResponse.SC_OK);
        }
        catch (AuthenticationException e)
        {
            logger.error("Login failed for {}", username, e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}
```

`logger.error("Login failed for {}", username, e)` resolves to the varargs overload. SLF4J binds `username` to the single `{}` placeholder and, because the trailing argument is a `Throwable` with no placeholder left for it, treats `e` as the exception - so the stack trace is still rendered exactly as the two-argument call rendered it.

If you would rather the username travelled as its own field than inside the message, `MDC.put("user", username)` in a try/finally around the handler gets the same encoding from the same encoder, and `LogstashEncoder` emits MDC entries as JSON fields.

Where a JSON appender genuinely cannot be adopted, the fallback is to encode the value before logging: escape the backslash first, then `\r`, `\n`, `\t`, the rest of `\x00-\x1F` and `\x7F` as `\uXXXX`, plus U+0085, U+2028 and U+2029. Escaping the backslash first is what keeps a literal `\` followed by `n` distinguishable from a real newline. Encode rather than strip, so the log still records that an injection was attempted, and truncate before encoding so a length cut cannot land inside an escape sequence.

## Explanation

The `user` request parameter reaches the log record unencoded, so a value ending in `%0d%0a` closes the real entry and writes attacker-chosen lines behind it - a forged "Login succeeded for admin", or padding that pushes the genuine failure out of an operator's view. The fix has two halves and needs both. Switching line 25 from concatenation to an SLF4J `{}` placeholder puts the untrusted value into a parameter slot instead of the message template, which is what lets the appender treat it as a data value with a boundary; on its own it changes nothing about what is written. Configuring the appender with `LogstashEncoder` supplies the encoding: each event becomes one JSON object per line, and control characters inside a field value are escaped as JSON string escapes, so CR and LF can no longer terminate the record. That also closes line 19, which was already parameterized and still forgeable under a plain-text layout. One residual to check against your pipeline: JSON encoding always escapes the ASCII control range, but Jackson-based encoders emit U+0085, U+2028 and U+2029 raw. Those forge an entry only where a line-oriented stage runs ahead of the JSON parser - Java's `Scanner` treats all three as terminators, while `BufferedReader.readLine()` does not - so verify how your shipper splits events, and fall back to explicit encoding of those three code points if it splits on them.

## Behaviour changes

- **Log message construction at line 25 changes from concatenation to a placeholder.** Under a plain-text layout the rendered line is identical; under the recommended JSON layout the text becomes a `message` field. Required: the placeholder is what gives the encoder a field boundary to encode within.
- **Stack trace rendering is preserved.** `e` moves from the explicit `Throwable` parameter to the varargs tail, where SLF4J still binds it as the throwable because no placeholder remains for it. No change to what is logged. Flagged because it is the one difference that would silently degrade the record if overload resolution went differently - a second `{}` in the template would demote `e` to a `toString()` argument and lose the stack trace.
- **Log output format changes to JSON application-wide**, for every logger, not only this class. Required: the encoder is the component that performs the neutralization, and it is configured per appender rather than per call site. Downstream consumers - log shippers, grep-based alerts, dashboards parsing plain-text lines - need re-pointing at the JSON fields before this ships. This is the largest blast radius in the fix and the part to stage first outside production.
- **A new runtime dependency is added** (`logstash-logback-encoder`), pulling in Jackson transitively. Required for the encoder. Resolve the version through SCA rather than pinning it from recall.
- **The stale `// SAST FINDING:` marker comment above the sink is removed.** No behavioural effect; it described the defect being fixed.
- **Not changed, deliberately:** the HTTP 401 response, the control flow, the log level, the success-path message text, and the value passed to `authenticator.authenticate`. No truncation or validation was added to `username` - the encoder handles neutralization, and a length cap or character allowlist would alter what gets recorded about an attack without closing anything the encoder leaves open.
