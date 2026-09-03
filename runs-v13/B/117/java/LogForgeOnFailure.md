## Verdict

Exploitable. Untrusted user input from `request.getParameter("user")` is concatenated directly into a log message at line 25 without any encoding or neutralization, allowing log injection attacks via special characters including newlines, null bytes, and Unicode line separators.

## Source

Line 14: `String username = request.getParameter("user");` - untrusted HTTP request parameter.

Data flows unencoded from the HTTP request to the logging sink at line 25.

## Fix

**Vulnerable code (line 25):**
```java
logger.error("Login failed for " + username, e);
```

**Fixed code:**
```java
logger.error("Login failed for {}", encodeForLog(username), e);
```

Add the following utility method to the `LogForgeOnFailure` class:

```java
private static String encodeForLog(String value) {
    if (value == null) return "null";
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < value.length(); i++) {
        char c = value.charAt(i);
        // Encode ASCII control characters (0x00-0x1F, 0x7F), 
        // Unicode line separators (U+0085, U+2028, U+2029), and backslash
        if ((c >= 0x00 && c <= 0x1F) || c == 0x7F || c == 0x85 || 
            c == 0x2028 || c == 0x2029 || c == '\\') {
            sb.append(String.format("\\u%04x", (int) c));
        } else {
            sb.append(c);
        }
    }
    return sb.toString();
}
```

## Explanation

The fix addresses log injection by encoding the untrusted username before it is written to the log. The `encodeForLog()` method escapes all ASCII control characters (0x00-0x1F and 0x7F), Unicode line separators (U+0085, U+2028, U+2029), and the backslash character itself using `\uXXXX` escapes. This prevents an attacker from using newlines or other control characters to forge additional log entries. The replacement also converts the string concatenation to parameterized logging with `{}` placeholders, which separates the message template from the value and prevents the untrusted data from being interpreted as part of the log format. The exception `e` remains as the final argument, which SLF4J correctly interprets as a throwable to be logged with the stack trace.

## Behaviour changes

- **Added `encodeForLog()` utility method** - ensures all dangerous characters are safely represented as Unicode escapes before logging, required to close the injection vector
- **Changed from string concatenation to parameterized logging** - uses `{}` placeholder instead of `+` operator; this separates template from value and is the safe pattern for SLF4J, preventing any encoded special characters in the username from being misinterpreted
- **Exception argument position unchanged** - the `e` (AuthenticationException) remains as the second argument to `logger.error()`, which SLF4J correctly interprets as the throwable to log with full stack trace
