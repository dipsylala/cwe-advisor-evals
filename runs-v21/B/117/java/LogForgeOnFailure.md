## Verdict

Exploitable. Untrusted user input from `request.getParameter("user")` flows directly into a log message via string concatenation without encoding, allowing an attacker to inject log control characters (newlines, null bytes, Unicode line separators) to forge log entries.

## Source

`request.getParameter("user")` on line 14 returns untrusted HTTP request parameter data.

## Fix

The vulnerability appears on line 25 where untrusted user input is concatenated directly into a log message. Additionally, line 19 uses parameterized logging but still lacks encoding. Both must be fixed according to CWE-117/java guidance to close all taint sinks.

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
            logger.info("Login succeeded for {}", encodeLogValue(username));
            response.setStatus(HttpServletResponse.SC_OK);
        }
        catch (AuthenticationException e)
        {
            logger.error("Login failed for {}", encodeLogValue(username), e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    private static String encodeLogValue(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if ((c >= 0x00 && c <= 0x1F) || c == 0x7F || c == 0x85 || c == 0x2028 || c == 0x2029 || c == '\\') {
                sb.append(String.format("\\u%04x", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
```

## Explanation

The fix encodes untrusted input before it reaches log sinks. A new helper method `encodeLogValue()` escapes all characters that can be exploited for log injection: ASCII control characters (0x00-0x1F), DEL (0x7F), Unicode line separators (U+0085, U+2028, U+2029), and backslash. These are converted to their `\uXXXX` Unicode escape form, preventing newlines and other control characters from forging new log entries or hiding malicious activity. The method is applied at both logging call sites (lines 19 and 25) to eliminate all untrusted data flows to log outputs. Using parameterized logging with `{}` placeholders keeps the message template separate from user data, providing structure that encoding-aware sinks can leverage. The Throwable argument remains as the trailing parameter to `logger.error()` per SLF4J convention.

## Behaviour changes

- Line 19: Changed from `logger.info("Login succeeded for {}", username)` to `logger.info("Login succeeded for {}", encodeLogValue(username))`. The encoded value is now written to logs instead of raw user input.
- Line 25: Changed from `logger.error("Login failed for " + username, e)` to `logger.error("Login failed for {}", encodeLogValue(username), e)`. String concatenation replaced with parameterized logging and the value is encoded before passing to the logger.
- Added `encodeLogValue(String)` private static method. This is a new helper that performs Unicode escape encoding on control characters and backslash, required to satisfy the CWE-117 remediation requirement of encoding untrusted data before logging.
