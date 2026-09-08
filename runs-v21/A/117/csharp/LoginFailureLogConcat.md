## Verdict

**Confirmed**

The code directly interpolates user-controlled input (username) into a log message using string interpolation. This allows an attacker to inject newlines and other control characters to corrupt log output, violating CWE-117 (Improper Output Neutralization for Logs).

## Source

Line 23 in LoginFailureLogConcat.cs:
```csharp
_logger.LogWarning($"Failed login attempt for user: {username}");
```

The `username` parameter originates from the `[FromForm]` attribute on line 18, making it attacker-controlled input.

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

The vulnerability stems from using string interpolation to concatenate user input directly into log messages. An attacker can craft a username containing newline characters (e.g., `admin\r\nINFO: User admin successfully authenticated`) to inject false log entries and corrupt the audit trail.

The fix uses structured logging by passing the username as a separate parameter to `LogWarning`. The placeholder `{Username}` declares the parameter name, and the actual value is passed as a separate argument. The ILogger framework handles proper escaping and serialization of the parameter value, preventing log injection while maintaining log integrity. This approach also enables better log parsing and filtering by treating the username as structured data rather than part of the message template.

