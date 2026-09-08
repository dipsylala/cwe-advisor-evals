## Verdict

Log injection vulnerability confirmed. The `username` parameter from the HTTP POST request is concatenated directly into the log message using string interpolation without encoding, allowing attackers to inject newlines and other control characters to forge log entries.

## Source

`username` parameter at line 18 enters from untrusted HTTP POST form data. It flows directly into the `LogWarning` call at line 23 via string interpolation.

## Fix

### File: LoginFailureLogConcat.cs

```csharp
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Text.RegularExpressions;

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
            var encodedUsername = Regex.Replace(username, @"[\x00-\x1F\x7F  \\]", m => $@"\u{(int)m.Value[0]:x4}");
            _logger.LogWarning("Failed login attempt for user: {Username}", encodedUsername);
            return Unauthorized();
        }

        return Ok();
    }

    private bool IsValidCredentials(string username, string password)
    {
        return false;
    }
}
```

## Explanation

The fix applies two remediation strategies from the C# CWE-117 guidance:

1. **Encoding at the call site**: The untrusted `username` is passed through `Regex.Replace()` with the pattern `@"[\x00-\x1F\x7F  \\]"` to escape all control characters that can be used for log injection (ASCII controls 0x00–0x1F, DEL 0x7F, Unicode line separators U+0085/U+2028/U+2029, and backslash). Each matched character is converted to the literal text `\uXXXX` format (e.g., a newline becomes the six-character sequence `
`), ensuring that a literal backslash-n and a real newline render differently in logs.

2. **Parameterized logging**: The call is changed from string interpolation (`$"Failed login attempt for user: {username}"`) to parameterized logging (`LogWarning("Failed login attempt for user: {Username}", encodedUsername)`), which separates the template from the data value. This allows encoding-aware sinks to operate correctly and prevents the value from being re-interpreted as part of the log message structure.

The fix closes the vulnerability under any logging configuration (plain text, Serilog JSON, or Microsoft.Extensions.Logging JSON) by encoding at the call site, rather than relying on the sink to handle control characters.

## Behaviour changes

- Log entries containing the previously vulnerable `username` parameter now have control characters escaped to their `\uXXXX` literal text representation, preventing log injection attacks.
- Legitimate usernames containing ordinary punctuation or non-ASCII text will be logged correctly; only control characters 0x00–0x1F, 0x7F, U+0085, U+2028, U+2029, and backslash will be escaped.
- The logging call signature changes from interpolated string to parameterized template with explicit parameter, with no change to the logged message structure under normal conditions.
