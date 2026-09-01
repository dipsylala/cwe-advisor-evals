## Verdict

Exploitable. The untrusted `username` parameter from the HTTP form is embedded directly into the log message via string interpolation at line 23, with no encoding or sanitization. An attacker can inject control characters (newlines, null bytes, Unicode line separators) to forge log entries or hide malicious activity.

## Source

`username` parameter from `[FromForm] string username` in the Login method - untrusted user input from HTTP form submission.

## Fix

**Vulnerable code (line 23):**
```csharp
_logger.LogWarning($"Failed login attempt for user: {username}");
```

**Fixed code:**
```csharp
_logger.LogWarning("Failed login attempt for user: {Username}", username);
```

## Explanation

The fix replaces string interpolation with a parameterized message template. Instead of embedding the username value into the message string at the call site, the template `{Username}` becomes a placeholder and the value is passed as a separate parameter to `LogWarning()`. This separates the message structure from the data, allowing the ILogger framework's configured formatters to properly encode the username value according to their encoding rules. The parameterized approach is required by C#'s logging best practices and enables the logging sink to neutralize special characters (ASCII controls 0x00-0x1F, DEL 0x7F, Unicode line separators U+0085/U+2028/U+2029, and backslash) when formatting the final log output, preventing log injection attacks.

## Behaviour changes

- The message template changes from interpolated format to a constant string with a placeholder: `$"..."` becomes `"..."` with a named placeholder `{Username}`
- The `username` value is now passed as a method parameter instead of being embedded in the string
- The logging framework receives structured data and applies encoding according to its configured formatter (Microsoft.Extensions.Logging's JSON formatter uses System.Text.Json which escapes the full control character range)
- The semantic log content remains identical: a warning is logged with the same information, but the value is properly encoded
- This also satisfies Roslyn analyzer CA2254, which flags non-constant message templates passed to logger methods

