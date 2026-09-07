## Verdict

Exploitable

## Source

**Source**: `String username = request.getParameter("user");` (line 14)
- Untrusted HTTP request parameter

**Sink**: `logger.error("Login failed for " + username, e);` (line 25)
- Direct string concatenation into SLF4J log message without encoding

**Data Flow**: Untrusted username from HTTP request is concatenated directly into a log message string, allowing attackers to inject control characters (newlines, null bytes, etc.) to forge log entries.

## Fix

**Vulnerable Code**:
```java
catch (AuthenticationException e)
{
    // SAST FINDING: CWE-117 (Improper Output Neutralization for Logs) reported here. Sink is the next statement.
    logger.error("Login failed for " + username, e);
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
}
```

**Fixed Code**:
```java
private static String encodeForLog(String input) {
    if (input == null) return null;
    StringBuilder sb = new StringBuilder();
    for (char c : input.toCharArray()) {
        // Encode ASCII control (0x00-0x1F), DEL (0x7F), Unicode line separators (U+0085, U+2028, U+2029), and backslash
        if ((c >= 0x00 && c <= 0x1F) || c == 0x7F || c == 0x85 || c == 0x2028 || c == 0x2029 || c == '\\') {
            sb.append(String.format("\\u%04x", (int) c));
        } else {
            sb.append(c);
        }
    }
    return sb.toString();
}

catch (AuthenticationException e)
{
    logger.error("Login failed for {}", encodeForLog(username), e);
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
}
```

## Explanation

The fix eliminates log injection by encoding the untrusted username parameter before it reaches the log sink. The encodeForLog helper method escapes all characters used for log forging: ASCII control characters (0x00-0x1F and 0x7F), Unicode line separators (U+0085, U+2028, U+2029), and the backslash itself. These are rendered as Unicode escape sequences (\\uXXXX), preventing attackers from injecting newlines or control characters that would appear as literal characters in output. The parameterized logging format ({} placeholder) keeps the message template separate from the value, ensuring encoding is the primary defence at the call site regardless of logging framework configuration.

## Behaviour changes

**Parameter passing change**: The original code passed username directly as part of string concatenation to logger.error(). The fixed code calls encodeForLog(username) to encode the value before passing it to the parameterized logging call.

**Message template change**: Changed from string concatenation ("Login failed for " + username) to SLF4J parameterized logging ("Login failed for {}" with encoded value as argument). This separates template from data, making the code cleaner and ensuring the logging framework can reliably encode the value if configured for structured logging.

**New helper method**: Added the encodeForLog() private static method to handle encoding. This method is called once per log statement containing untrusted data and adds minimal performance overhead.

**Exception argument positioning**: The exception e moves from the second position in the original call to the third position (after the encoded username parameter). This follows the correct SLF4J convention: message template, arguments, then exception.

**Verification**: Code compiles with standard Java library only (StringBuilder, String). SLF4J Logger.error(String, Object, Throwable) method signature is correctly matched with message, encoded argument, and exception. No external dependencies introduced beyond SLF4J which is already in scope.

**Assumptions**: Assumed autonomous mode context. The encodeForLog() method is added as a private static utility to the LogForgeOnFailure class. SLF4J is already available (imported at line 5). No external encoding library dependency is assumed.
