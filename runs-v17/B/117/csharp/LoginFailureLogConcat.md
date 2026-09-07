## Verdict

Exploitable. The untrusted `username` parameter from the HTTP form request is logged directly with string interpolation without encoding control characters, allowing attackers to inject newlines or other log control characters to forge log entries.

## Source

Line 18: `[FromForm] string username` parameter in the `Login` method. This is untrusted user input from an HTTP form submission.

## Sink

Line 23: `_logger.LogWarning($"Failed login attempt for user: {username}")` - the username is interpolated directly into the log message string.

## Fix

### File: LoginFailureLogConcat.cs

```csharp
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Text;

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
            var encodedUsername = EscapeLogValue(username);
            _logger.LogWarning("Failed login attempt for user: {Username}", encodedUsername);
            return Unauthorized();
        }

        return Ok();
    }

    private bool IsValidCredentials(string username, string password)
    {
        return false;
    }

    private static string EscapeLogValue(string value)
    {
        if (string.IsNullOrEmpty(value))
            return value;
        
        var result = new StringBuilder();
        foreach (var c in value)
        {
            switch (c)
            {
                case '\x00': result.Append("\x00"); break;
                case '\x01': result.Append("\x01"); break;
                case '\x02': result.Append("\x02"); break;
                case '\x03': result.Append("\x03"); break;
                case '\x04': result.Append("\x04"); break;
                case '\x05': result.Append("\x05"); break;
                case '\x06': result.Append("\x06"); break;
                case '\x07': result.Append("\x07"); break;
                case '\x08': result.Append("\x08"); break;
                case '\x09': result.Append("\t"); break;
                case '\x0A': result.Append("\n"); break;
                case '\x0B': result.Append("\x0B"); break;
                case '\x0C': result.Append("\f"); break;
                case '\x0D': result.Append("\r"); break;
                case '\x0E': result.Append("\x0E"); break;
                case '\x0F': result.Append("\x0F"); break;
                case '\x10': result.Append("\x10"); break;
                case '\x11': result.Append("\x11"); break;
                case '\x12': result.Append("\x12"); break;
                case '\x13': result.Append("\x13"); break;
                case '\x14': result.Append("\x14"); break;
                case '\x15': result.Append("\x15"); break;
                case '\x16': result.Append("\x16"); break;
                case '\x17': result.Append("\x17"); break;
                case '\x18': result.Append("\x18"); break;
                case '\x19': result.Append("\x19"); break;
                case '\x1A': result.Append("\x1A"); break;
                case '\x1B': result.Append("\x1B"); break;
                case '\x1C': result.Append("\x1C"); break;
                case '\x1D': result.Append("\x1D"); break;
                case '\x1E': result.Append("\x1E"); break;
                case '\x1F': result.Append("\x1F"); break;
                case '\x7F': result.Append("\x7F"); break;
                case '\u0085': result.Append("\u0085"); break;
                case '\u2028': result.Append("\u2028"); break;
                case '\u2029': result.Append("\u2029"); break;
                case '\': result.Append("\\\\"); break;
                default:
                    result.Append(c);
                    break;
            }
        }
        return result.ToString();
    }
}
```

## Explanation

The vulnerability occurs because the untrusted `username` parameter from the HTTP form request is interpolated directly into a log message without encoding control characters. An attacker can inject newlines (CRLF), null bytes, or Unicode line separators to forge fake log entries, hide malicious activity, or cause log injection attacks. The fix encodes all dangerous characters at the call site before logging: ASCII control characters (0x00-0x1F), DEL (0x7F), Unicode line separators (U+0085, U+2028, U+2029), and backslash itself (to distinguish a literal backslash-n from a real newline). The logging call is also changed from string interpolation to a message template pattern (`logger.LogWarning("...", encodedUsername)`), which separates the template from the value and allows encoding-aware sinks to operate on the separated data. This combination closes the injection vector regardless of the logging sink configuration.

## Behaviour changes

1. **Added import**: `using System.Text;` for the `StringBuilder` class used in the encoding helper.
2. **Added method**: `EscapeLogValue` private static method that encodes dangerous control characters. This method iterates through each character in the input and replaces control characters, DEL, Unicode line separators, and backslashes with their escaped representations.
3. **Modified logging call**: Line 23 changed from `_logger.LogWarning($"Failed login attempt for user: {username}")` to use an encoded value and message template: `_logger.LogWarning("Failed login attempt for user: {Username}", encodedUsername)`. This separates template from value and ensures the encoding is applied.
4. **Intermediate variable**: Added `var encodedUsername = EscapeLogValue(username);` to hold the encoded value, keeping the logic clear.

No other behavior changes. The method still returns `Unauthorized()` on failed credentials, and the control flow is identical to the original.
