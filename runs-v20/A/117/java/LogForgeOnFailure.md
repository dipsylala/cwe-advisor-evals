## Verdict
Confirmed: CWE-117. `username` is read from an untrusted HTTP request parameter and passed unsanitized into `logger.error(...)` (and also into the `logger.info` call on the success path). SLF4J's `{}` parameterization does not encode or strip control characters from parameter values, so an attacker who supplies a `user` value containing CR/LF (e.g. `attacker\n2026-01-01 00:00:00 INFO Login succeeded for admin`) can inject fake log lines or corrupt log structure.

## Source
`request.getParameter("user")` on line 14, flowing unsanitized into `logger.error("Login failed for " + username, e)` on line 25 (and into `logger.info("Login succeeded for {}", username)` on line 19).

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
        String username = sanitizeForLog(request.getParameter("user"));

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

    private static String sanitizeForLog(String value)
    {
        if (value == null)
        {
            return null;
        }
        return value.replaceAll("[\\r\\n\\t]", "_");
    }
}
```

## Explanation
The untrusted `username` is neutralized once, immediately after it is read from the request, rather than at each log call site — this closes the finding at line 25 and the identical exposure at line 19 without duplicating sanitization logic. `sanitizeForLog` replaces carriage return, line feed, and tab characters (the characters that let an attacker split a log entry into what looks like multiple separate log lines or shift columns in a delimited log format) with an underscore, so an attacker-controlled value can no longer forge additional log records or corrupt log parsing; it is a rejection-free transform that preserves the original value's readability for legitimate usernames (which don't contain control characters) while defusing the injection for malicious ones.

The `logger.error` call was also changed from string concatenation (`"Login failed for " + username`) to SLF4J parameterized form (`"Login failed for {}", username, e`) to match the sanitized-input pattern used on the success path and avoid string-building the message eagerly; the sanitization is what actually neutralizes the injection, since SLF4J's `{}` substitution does not itself encode or strip control characters from the parameter's value.
