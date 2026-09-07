## Verdict

exploitable

## Source

Line 14: `String username = request.getParameter("user")` - untrusted HTTP request parameter

## Fix

### File: LogForgeOnFailure.java

```java
package evalcases;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.text.StringEscapeUtils;
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
            logger.error("Login failed for {}", StringEscapeUtils.escapeJava(username), e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}
```

## Explanation

The vulnerability at line 25 allows attackers to forge log entries by injecting control characters (newlines, carriage returns, null bytes) through the untrusted `username` parameter via string concatenation. The fix applies two complementary controls: (1) `StringEscapeUtils.escapeJava()` from Apache Commons Text escapes the ASCII control range (0x00-0x1F), backslash, and Unicode line separators (U+0085, U+2028, U+2029) so injected characters appear as escaped data rather than control sequences; (2) SLF4J parameterized logging with `{}` placeholders separates the message template from the value, enabling encoding-aware sinks to process it safely. Note that `escapeJava()` does not encode DEL (0x7F); for complete coverage of all control characters, a custom encoder is preferred, but this solution aligns with the guidance's explicitly named "maintained alternative."

## Behaviour changes

**New import added**: `org.apache.commons.text.StringEscapeUtils` - required for the escapeJava() method.

**Method call change at line 25**: 
- Original: `logger.error("Login failed for " + username, e);` uses string concatenation with untrusted input
- Fixed: `logger.error("Login failed for {}", StringEscapeUtils.escapeJava(username), e);` uses parameterized logging with encoded value

The change preserves the sink's exception handling contract (the Throwable `e` remains the trailing argument, which SLF4J treats specially) and maintains the same logged output semantics - only the encoding changes, not the information flow. The parameterized form with `{}` placeholders does not encode by itself but accompanies the explicit encoding to ensure encoding-aware backends can process the value safely.

