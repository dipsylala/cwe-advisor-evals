## Verdict

Exploitable. Untrusted user input from the `username` form parameter is directly interpolated into a log message via string interpolation, allowing attackers to inject newline characters and Unicode line separators to forge log entries or break log parsing.

## Source

The `username` parameter on line 18 is sourced from `[FromForm] string username`, which represents untrusted HTTP form input. An attacker can control this value via the login form.

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
            // Encode special characters to prevent log injection
            var encodedUsername = Regex.Replace(username, @"[\x00-\x1F\x7F\u0085\u2028\u2029\\]", m => $@"\u{(int)m.Value[0]:x4}");
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

The fix addresses the log injection vulnerability through two complementary changes:

1. **Character Encoding**: The username is passed through `Regex.Replace` to encode all characters that can break log format or inject entries: ASCII control characters (0x00-0x1F), DEL (0x7F), and Unicode line separators (U+0085, U+2028, U+2029), plus the backslash itself. Each matched character is replaced with its Unicode escape sequence (`\uXXXX`), so a literal newline becomes the six-character text `\u000a` instead of a line break. This encoding is independent of the logging formatter configuration and works with any sink.

2. **Message Template**: The log call is changed from string interpolation (`$"Failed login attempt for user: {username}"`) to a parameterized message template (`LogWarning("Failed login attempt for user: {Username}", encodedUsername)`). While the message template alone does not encode (it requires an encoding-aware formatter), it separates the template from the data, allowing compatible sinks to apply their own encoding and serving as a secondary control. The template pattern follows ASP.NET best practices and satisfies the Roslyn analyzer rule CA2254.

Together, these changes prevent attackers from forging log entries or injecting control sequences through the username field.

## Behaviour changes

- **Added import**: `using System.Text.RegularExpressions;` - required for the `Regex.Replace` call
- **New local variable**: `encodedUsername` - holds the sanitized username value
- **Changed log message format**: From string interpolation to parameterized message template - this prevents accidental format mismatches if the template is later modified and is aligned with ASP.NET Core logging best practices, but requires no changes to the method's external contract or return value
- **Encoded value passed to logger**: The logger now receives the encoded value instead of raw input - this may cause log entries to appear with escape sequences visible to human readers (for example, a newline in the username appears as `\u000a`), which is the intended behavior to preserve log integrity
