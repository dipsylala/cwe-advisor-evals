## Verdict

The finding is confirmed. Line 25 concatenates untrusted user input directly into a log message without encoding, enabling log injection attacks where newlines, control characters, and Unicode line separators can forge log entries or hide malicious activity.

## Source

**Line 13:** User input source
```java
String username = request.getParameter("user");
```

**Line 25:** Vulnerable sink - string concatenation in logging
```java
logger.error("Login failed for " + username, e);
```

**Data flow:** HTTP request parameter `user` flows directly into the log message without validation or encoding.

## Fix

Add a helper method to encode control characters and replace both logging statements to use parameterized logging with encoded input:

**Helper method to add to the class:**
```java
private static String encodeForLogging(String input) {
    if (input == null) {
        return null;
    }
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < input.length(); i++) {
        char c = input.charAt(i);
        // Encode ASCII control range (0x00-0x1F), DEL (0x7F), U+0085, U+2028, U+2029, and backslash
        if ((c >= 0x00 && c <= 0x1F) || c == 0x7F || c == 0x85 || c == 0x2028 || c == 0x2029 || c == '\\') {
            sb.append(String.format("\\u%04x", (int) c));
        } else {
            sb.append(c);
        }
    }
    return sb.toString();
}
```

**Line 20 - Replace:**
```java
logger.info("Login succeeded for {}", username);
```
**With:**
```java
logger.info("Login succeeded for {}", encodeForLogging(username));
```

**Line 25 - Replace:**
```java
logger.error("Login failed for " + username, e);
```
**With:**
```java
logger.error("Login failed for {}", encodeForLogging(username), e);
```

## Explanation

The fix closes CWE-117 by encoding untrusted user input before logging. The `encodeForLogging()` method escapes the ASCII control range (0x00-0x1F), DEL (0x7F), Unicode line separators (U+0085, U+2028, U+2029), and backslash as `\uXXXX` Unicode escape sequences. This prevents attackers from injecting newlines or other control characters to forge log entries, manipulate the audit trail, or hide security events.

String concatenation is replaced with SLF4J parameterized logging using `{}` placeholders, which separates the message template from the data and allows encoding-aware sinks to properly process the value. The Throwable argument `e` is correctly positioned as the last parameter to SLF4J, preserving exception logging in the original error message.

Both the login success path (line 20) and the login failure path (line 25) are fixed because both carry untrusted user data to log sinks, and fixing only the reported line leaves the same vulnerability exposed through alternate code paths.

## Behaviour changes

- Usernames containing newlines, null bytes, or Unicode line separators will be logged as escaped sequences (e.g., `user
name` instead of a literal newline that would forge a new log entry)
- Backslashes in usernames are escaped (e.g., `\`) so a literal backslash-n cannot be confused with a real newline character
- Both successful and failed login attempts now apply encoding consistently
- Legitimate usernames with ordinary punctuation or non-ASCII text (letters, digits, hyphens, etc.) continue to log correctly—only control characters and line separators are escaped
- Log output is now safe to aggregate, parse, and monitor without risk of injected false entries
