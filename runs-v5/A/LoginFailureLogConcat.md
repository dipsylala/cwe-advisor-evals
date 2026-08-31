## Verdict

Confirmed. The `username` value from the login form is written into the warning log via string
interpolation with no neutralization of control characters, so an attacker can inject CR/LF (or
other characters a log viewer interprets specially) to forge additional log lines or corrupt the
log record.

## Source

`username` — bound from the request body by `[FromForm] string username` on
`AccountController.Login`, `LoginFailureLogConcat.cs` line 18. It reaches the sink unvalidated:
`IsValidCredentials` only checks the credential, it does not constrain the characters allowed in
`username`.

## Fix

```csharp
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace EvalCases.Cwe117;

[ApiController]
[Route("account")]
public class AccountController : ControllerBase
{
    private static readonly Regex ControlChars = new(@"[\r\n\t\p{C}]", RegexOptions.Compiled);

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
            var sanitizedUsername = ControlChars.Replace(username ?? string.Empty, "_");
            _logger.LogWarning("Failed login attempt for user: {Username}", sanitizedUsername);
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

Two independent changes close the gap:

1. **Structured logging instead of string interpolation.** `LogWarning($"... {username}")` bakes
   the raw value into the format string before the logging framework ever sees it, so nothing
   downstream can treat it as data. Passing `username` as a message-template argument
   (`"... {Username}", sanitizedUsername`) keeps it as a discrete, named field so structured sinks
   (JSON, Serilog, Application Insights, etc.) emit it as its own attribute rather than splicing it
   into the free-text message, which removes one avenue for forged entries even before
   sanitization is considered.
2. **Explicit neutralization of control characters.** Structured logging alone does not stop
   injection for text-formatted sinks (the default console/file formatters still render the
   parameter inline in the message), so `username` is stripped of `\r`, `\n`, `\t`, and other
   Unicode control characters before it is logged. This is done on a local copy used only for
   logging — the original `username` is left untouched for authentication — so an attacker who
   submits a username containing `Failed login attempt for user: admin\r\n[INFO] Login succeeded`
   can no longer split that payload into a second, fabricated log line.

Both changes are additive to the existing control flow: the sink still fires once per failed
login attempt, and `IsValidCredentials` and the `Unauthorized()` response are unchanged.
