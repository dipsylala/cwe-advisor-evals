## Verdict

CWE-117 (Improper Output Neutralization for Logs) - exploitable. Confidence: high.

- **Location**: `LoginFailureLogConcat.cs`, line 23, inside `AccountController.Login`.
- **Assumptions**: none needed beyond the standard ASP.NET Core model-binding behavior noted below.

## Source

`username`, bound from the request body via `[FromForm] string username` on the `Login` action (`POST /account/login`). This is attacker-controlled HTTP form data with no length limit, character allowlist, or encoding applied before it reaches the log call.

## Fix

Vulnerable code:

```csharp
[HttpPost("login")]
public IActionResult Login([FromForm] string username, [FromForm] string password)
{
    if (!IsValidCredentials(username, password))
    {
        // SAST FINDING: CWE-117 (Improper Output Neutralization for Logs) reported here. Sink is the next statement.
        _logger.LogWarning($"Failed login attempt for user: {username}");
        return Unauthorized();
    }

    return Ok();
}
```

Fixed code:

```csharp
using System.Text;
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

    // Escapes the ASCII control range, DEL, the Unicode line/paragraph separators, and the
    // backslash itself, so a value cannot forge additional log lines or fields, and so a
    // literal backslash-n typed by an attacker cannot be mistaken for a real newline once
    // other characters have been turned into \uXXXX escapes.
    private static string SanitizeForLog(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        var sb = new StringBuilder(value.Length);
        foreach (char c in value)
        {
            if (c == '\\')
            {
                sb.Append("\\\\");
            }
            else if (c <= '\x1F' || c == '\x7F' || c == '\u0085' || c == '\u2028' || c == '\u2029')
            {
                sb.Append("\\u").Append(((int)c).ToString("x4"));
            }
            else
            {
                sb.Append(c);
            }
        }

        return sb.ToString();
    }
}
```

## Explanation

The sink took `username` straight from form data and spliced it into the log message with string interpolation, so any CR/LF, other ASCII control character, or Unicode line separator (U+0085/U+2028/U+2029) in the submitted username would forge additional log lines or fields in the audit trail. The fix adds a `SanitizeForLog` helper that escapes the full range this weakness covers - ASCII controls (`0x00`-`0x1F`), DEL (`0x7F`), the three Unicode separators, and the backslash itself (checked first, so a literal `\` typed by an attacker is escaped to `\\` before any other character in the string is turned into a `\uXXXX` escape, keeping the two visually distinct) - and logs the escaped value in place of the raw one. The call is also switched from string interpolation to a parameterized message template (`"...{Username}", SanitizeForLog(username)`), matching the C# guidance's note on `CA2254`; that change alone would neutralize nothing, so it is paired with the encoding rather than substituted for it. This closes the finding regardless of which log formatter or sink the application is ultimately configured with, without depending on a move to structured JSON logging.

## Behaviour changes

- The logged value for a username containing control characters, a backslash, or a Unicode line separator now appears with those characters rendered as `\uXXXX` escapes instead of literally. This is the intended effect of the fix. A username containing only ordinary printable characters logs identically to before.
- The log call changed from string interpolation to a parameterized template (`LogWarning("...{Username}", value)`); this only affects how the message is constructed internally and does not change the log level, the returned `IActionResult`, or any other control flow.
- No other behavior, return value, or argument was changed.
