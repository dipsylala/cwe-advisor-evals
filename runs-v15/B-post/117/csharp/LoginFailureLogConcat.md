## Verdict

Exploitable. Untrusted user input (`username` parameter) flows directly to the logging sink via string interpolation without any encoding or validation.

## Source

HTTP request parameter `username` from `[FromForm] string username` at line 18. This parameter is attacker-controlled and user-supplied.

## Fix

**Vulnerable code (line 23):**
```csharp
_logger.LogWarning($"Failed login attempt for user: {username}");
```

**Fixed code:**
```csharp
_logger.LogWarning("Failed login attempt for user: {Username}", SanitizeForLogging(username));

private string SanitizeForLogging(string input)
{
    if (string.IsNullOrEmpty(input))
        return input;
    
    var result = new StringBuilder();
    foreach (char c in input)
    {
        // Escape ASCII control range (0x00-0x1F, 0x7F), U+0085, U+2028, U+2029, and backslash
        if ((c >= '\x00' && c <= '\x1F') || c == '\x7F' || c == '' || c == ' ' || c == ' ' || c == '\\')
        {
            result.AppendFormat("\\u{0:X4}", (int)c);
        }
        else
        {
            result.Append(c);
        }
    }
    return result.ToString();
}
```

Add `using System.Text;` at the top of the file for `StringBuilder`.

## Explanation

The fix closes the log injection vulnerability by using two complementary defenses: (1) **Encoding at the call site**: the `SanitizeForLogging()` method escapes all characters that could forge or break out of a log entry—ASCII control characters (0x00-0x1F, 0x7F) plus Unicode line separators (U+0085, U+2028, U+2029) and the backslash itself. This ensures that an attacker-supplied newline or other control character renders as an escaped sequence, not as a structural element of the log. (2) **Parameterized message template**: replacing string interpolation (`$"..."`) with a message template (`"Failed login attempt for user: {Username}"`) separates the format string from the data value, which allows encoding-aware sinks to act correctly and complies with the Roslyn analyzer rule CA2254. Together, these changes neutralize log injection under any formatter configuration, including plain-text and JSON sinks.

## Behaviour changes

The sanitized username is passed to the logger as a parameter instead of interpolated into the message string. Any non-ASCII control characters and Unicode line separators in the username will now appear as `\uXXXX` escape sequences in the log output instead of as literal characters. This preserves the original username value for audit purposes (the presence of the escape sequence proves an injection attempt was made) while preventing forged log entries. Legitimate usernames containing ordinary punctuation or non-ASCII text will still read correctly after escaping.
