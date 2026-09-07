## Verdict
CONFIRMED

## Source
User-supplied `username` parameter from the HTTP request is directly interpolated into a log message at line 23, enabling log injection attacks.

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
            // SAST FINDING: CWE-117 (Improper Output Neutralization for Logs) reported here. Sink is the next statement.
            _logger.LogWarning("Failed login attempt for user: {Username}", username);
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
The vulnerability arises from string interpolation of untrusted user input into log messages. String interpolation does not escape special characters, allowing an attacker to inject newlines, braces, and other characters to manipulate log output or mask malicious activity.

The fix uses structured logging: a format string with a placeholder (`{Username}`) and the value passed as a separate parameter. The `ILogger` implementation automatically escapes user-supplied values when they are bound to named parameters, preventing injection of control characters or log formatting directives. This is the idiomatic C# pattern for safe logging via Microsoft.Extensions.Logging.
