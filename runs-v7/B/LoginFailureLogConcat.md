## Verdict

CWE-117 confirmed. Untrusted `username` parameter is directly interpolated into a log message via string interpolation without encoding, allowing log injection attacks.

## Source

Line 23: `_logger.LogWarning($"Failed login attempt for user: {username}");`

The `username` value originates from form input (line 18) and flows directly into the log sink.

## Fix

Replace string interpolation with a message template and encode the username to neutralize control characters:

```csharp
using System.Text.Encodings.Web;

[HttpPost("login")]
public IActionResult Login([FromForm] string username, [FromForm] string password)
{
    if (!IsValidCredentials(username, password))
    {
        var encodedUsername = JavaScriptEncoder.Default.Encode(username);
        _logger.LogWarning("Failed login attempt for user: {Username}", encodedUsername);
        return Unauthorized();
    }

    return Ok();
}
```

Key changes:
1. Replace string interpolation (`$"..."`) with a message template (`"Failed login attempt for user: {Username}"`) to satisfy the constant-template requirement (Roslyn CA2254).
2. Encode `username` using `JavaScriptEncoder.Default.Encode()` at the call site to escape ASCII controls (0x00-0x1F), DEL (0x7F), U+0085, U+2028, U+2029, and backslash, ensuring control characters cannot break out of the log entry.
3. Pass the encoded value to the logger as a named parameter so it binds to the `{Username}` placeholder.

## Explanation

String interpolation in log calls allows attackers to inject newlines and control characters directly into log output, forging log entries and obscuring audit trails. Encoding at the call site closes this attack by ensuring such characters are escaped and appear as literal data, not as log control sequences. The message template form (with named placeholders) is a prerequisite in .NET: it separates the message structure from the data, and complies with the Roslyn rule CA2254 that flags non-constant templates. `JavaScriptEncoder.Default.Encode()` is part of `System.Text.Encodings.Web` (included in .NET Standard 2.1+) and escapes the full range of characters needed for log safety regardless of which formatter the logger is configured with—both `Microsoft.Extensions.Logging`'s JSON formatter and Serilog's.

## Behaviour changes

- Newlines, tabs, carriage returns, and other control characters in the username are now escaped (e.g., newline becomes `
` in the log output).
- The username is now output as a named field `Username` in the log, which improves structure and is compatible with structured logging frameworks.
- Performance: encoding adds minimal overhead; `JavaScriptEncoder` is optimized for this use case.
- Log readability: legitimate usernames with ordinary punctuation or non-ASCII text (e.g., names with accents) still appear correctly, because encoding preserves the character and only escapes control sequences.
