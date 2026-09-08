## Verdict

Confirmed. `username` is attacker-controlled input (bound directly from the form body via `[FromForm]`) and is written into the log message by string interpolation with no neutralization of newline or other control characters. An attacker can submit a `username` value containing `\r\n` to inject fake log records or corrupt log parsing/analysis (log forging).

## Source

`E:/Github/cwe-advisor/evals/cases/117/csharp/LoginFailureLogConcat/LoginFailureLogConcat.cs`, line 18: the `username` parameter of `Login`, bound from the request via `[FromForm] string username`. It flows unmodified into the `_logger.LogWarning($"Failed login attempt for user: {username}")` call at line 23.

## Fix

### File: LoginFailureLogConcat.cs

```csharp
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace EvalCases.Cwe117;

[ApiController]
[Route("account")]
public class AccountController : ControllerBase
{
    private readonly ILogger<AccountController> _logger;

    public AccountController(ILogger<AccountController> logger)
    {
        _logger = logger;
    }

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

    private bool IsValidCredentials(string username, string password)
    {
        return false;
    }

    // Neutralizes characters that allow log forging (CR, LF, and other control
    // characters) so a single attacker-controlled value cannot span multiple
    // log lines or inject fields into structured log output.
    private static string SanitizeForLog(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var sanitized = new System.Text.StringBuilder(value.Length);
        foreach (var c in value)
        {
            if (c == '\r' || c == '\n')
            {
                sanitized.Append(' ');
            }
            else if (char.IsControl(c))
            {
                sanitized.Append('_');
            }
            else
            {
                sanitized.Append(c);
            }
        }

        return sanitized.ToString();
    }
}
```

## Explanation

The finding is that `username` reaches the logger with no neutralization, so a value such as `alice\r\nINFO: admin login succeeded` becomes two log lines, letting an attacker forge or split log entries and mislead anything that parses the log (SIEM rules, log-based alerting, an operator reading the file). ASP.NET Core's `ILogger` does not neutralize control characters in interpolated message text on its own, so the check has to happen before the value is handed to the logger.

The fix replaces the string-interpolated message with a structured logging template (`{Username}`) and passes the value through `SanitizeForLog`, which strips the two characters that actually create new log records (`\r`, `\n`, replaced with a space so the message stays readable) and neutralizes any other control character (replaced with `_`) that could otherwise corrupt line-based or structured log output. This targets the actual defect - unneutralized control characters - without rejecting or altering any other content of the username, so legitimate usernames (including ones with spaces, punctuation, or non-ASCII characters) are logged unchanged. Switching to the structured-logging overload is a defense-in-depth measure: it keeps the username as a distinct, named field for log processors that understand `ILogger`'s structured output, while the explicit sanitization guarantees safety even when the log is consumed as flat text by tools that do not.
