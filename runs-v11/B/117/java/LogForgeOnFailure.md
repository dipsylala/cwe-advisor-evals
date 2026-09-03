## Verdict

Confirmed. CWE-117: Improper Output Neutralization for Logs at line 25.

## Source

The untrusted `username` parameter originates from HTTP request input via `request.getParameter("user")` (line 14). This value flows directly to the log sink via string concatenation at line 25 without encoding or validation.

## Fix

**Vulnerable code (line 25):**
```java
logger.error("Login failed for " + username, e);
```

**Fixed code:**
```java
logger.error("Login failed for {}", StringEscapeUtils.escapeJava(username), e);
```

**Required import:**
```java
import org.apache.commons.text.StringEscapeUtils;
```

## Explanation

The vulnerability allows an attacker to inject log control characters (newlines, null bytes, Unicode line separators) by providing a malicious username parameter, which forges additional log entries and obscures security events in audit trails.

The fix replaces string concatenation with SLF4J parameterized logging using `{}` placeholders, which separates the message template from the data value. Additionally, `StringEscapeUtils.escapeJava()` from Apache Commons Text encodes the ASCII control range (0x00-0x1F), DEL (0x7F), U+0085, U+2028, U+2029, and the backslash itself, ensuring that control characters are rendered as visible escape sequences rather than being interpreted by the logging framework.

The existing successful login message at line 19 already uses the placeholder pattern; this fix aligns the error case with that established safe pattern while adding explicit encoding for defense-in-depth.

## Behaviour changes

- Log messages containing injected newlines, null bytes, or other control characters will now escape those characters (e.g., `\n`, `\x00`) instead of interpreting them as log entry separators, preserving log integrity.
- Legitimate usernames containing ordinary punctuation or Unicode characters will continue to render correctly after encoding.
- The exception stack trace remains attached to the log entry and is handled separately as the final argument to `logger.error()`.
