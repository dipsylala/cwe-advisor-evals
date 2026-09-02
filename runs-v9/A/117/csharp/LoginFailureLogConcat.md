## Verdict

Confirmed. The `username` value from the login form is written into the log record with no neutralization, so an attacker can inject CR/LF and other control characters into the log stream.

## Source

`Login(...)` in `AccountController` receives `username` from `[FromForm] string username` (line 18) — attacker-controlled request data.

## Fix

```csharp
[HttpPost("login")]
public IActionResult Login([FromForm] string username, [FromForm] string password)
{
    if (!IsValidCredentials(username, password))
    {
        _logger.LogWarning("Failed login attempt for user: {Username}", SanitizeForLog(username));
        return Unauthorized();
    }

    return Ok();
}

private static string SanitizeForLog(string? value)
{
    if (string.IsNullOrEmpty(value))
    {
        return string.Empty;
    }

    // Strip control characters (including CR/LF) that could forge or split log entries.
    var sanitized = new string(value.Where(c => !char.IsControl(c)).ToArray());

    const int maxLength = 256;
    return sanitized.Length > maxLength ? sanitized[..maxLength] : sanitized;
}
```

(Add `using System.Linq;` if not already present.)

## Explanation

Line 23 builds the log message with a C# interpolated string, `$"Failed login attempt for user: {username}"`, and passes the fully-formed string straight to `LogWarning`. Because `username` comes directly from the HTTP form body, an attacker can submit a value containing `\r\n` (or other control characters) to inject fake log lines, spoof additional "log entries" that never happened, or break downstream log parsing/SIEM rules that assume one event per line — the classic CWE-117 log-forging pattern.

The fix does two things:

1. **Switches to structured/semantic logging** — `_logger.LogWarning("... {Username}", value)` instead of string interpolation. `ILogger` treats `{Username}` as a named parameter rather than baking the raw value into the template, which keeps the message template constant (attacker input can never alter the template itself) and lets structured-logging sinks (e.g. JSON log providers) store the value as a discrete field instead of raw text.
2. **Strips control characters before the value ever reaches the logger** — `SanitizeForLog` removes any `char.IsControl` character (this covers `\r`, `\n`, and other non-printable bytes) so the value cannot split or forge log lines even with a plain-text formatter/sink, and truncates to a reasonable length to limit log-flooding from oversized input.

Together these ensure the untrusted `username` can no longer alter the structure of the log stream, while the log message still records the attempted (sanitized) username for auditing.
