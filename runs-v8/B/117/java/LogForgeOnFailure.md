## Verdict

Exploitable. The untrusted `username` parameter is concatenated directly into a log message without encoding, allowing injection of newline characters and other control characters to forge or manipulate log entries.

## Source

Line 14: `String username = request.getParameter("user");` — untrusted HTTP request parameter flows into the variable without validation.

## Fix

**Vulnerable code:**
```java
logger.error("Login failed for " + username, e);
```

**Fixed code:**
```java
logger.error("Login failed for {}", encodeLogValue(username), e);
```

Where `encodeLogValue()` is a helper method that encodes control characters:

```java
private static String encodeLogValue(String value) {
    if (value == null) return null;
    StringBuilder sb = new StringBuilder();
    for (char c : value.toCharArray()) {
        // Encode ASCII control range (0x00-0x1F), DEL (0x7F), Unicode separators, and backslash
        if ((c >= 0x00 && c <= 0x1F) || c == 0x7F || c == 0x0085 || c == 0x2028 || c == 0x2029 || c == '\\') {
            sb.append(String.format("\\u%04x", (int) c));
        } else {
            sb.append(c);
        }
    }
    return sb.toString();
}
```

## Explanation

The fix encodes the untrusted `username` value at the call site before it reaches the logger, escaping all ASCII control characters (0x00-0x1F and 0x7F), Unicode line separators (U+0085, U+2028, U+2029), and the backslash character as Unicode escape sequences. This prevents control characters like newlines from being interpreted as log control sequences, eliminating log injection. The fix also switches from string concatenation to SLF4J's parameterized logging with `{}` placeholders, which keeps the template separate from the value and supports encoding-aware sinks. The exception is preserved as the trailing argument per SLF4J conventions.

## Behaviour changes

None. The encoding produces a logged string that contains escaped control characters in human-readable form (e.g., `
` instead of a raw newline), preserving the evidence of injection attempts. The log message still conveys the same semantic information: a failed authentication for a particular username. The Throwable argument is preserved in the same position, maintaining exception logging behavior.
