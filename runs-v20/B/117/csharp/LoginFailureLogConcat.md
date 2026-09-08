## Verdict

Exploitable. Confidence: high.

CWE-117 (Improper Output Neutralization for Logs). The `username` value from the failed-login request is written into the log message via string interpolation with no encoding or validation anywhere on the path, so an attacker who submits a username containing CR/LF or other control characters can forge additional log lines or corrupt the audit trail.

## Source

- **Source**: `username`, bound directly from the request body by `[FromForm] string username` on `AccountController.Login` (`LoginFailureLogConcat.cs:18`). Fully attacker-controlled, no length or character restriction.
- **Path**: `username` is passed to `IsValidCredentials(username, password)`, which always returns `false` and does not transform, validate, or otherwise touch either argument. Control returns to `Login`, and on the `false` branch `username` reaches the sink unchanged.
- **Sink**: `_logger.LogWarning($"Failed login attempt for user: {username}")` at `LoginFailureLogConcat.cs:23`. The interpolated string is fully materialized before it reaches `ILogger.LogWarning`, so the value is spliced into the log message as raw text with no separation between template and data and no encoding of control characters.
- **Sink contract**: `LogWarning` returns `void`; nothing depends on a return value. With a compile-time interpolated string there is no discarded structured payload - the whole message, including the attacker's characters, is the produced text. No arguments are omitted (a plain message overload is used, no scope or exception object involved). Failure behavior: `ILogger` implementations swallow logging failures rather than throwing, so no caller error handling depends on this call.

No sanitization, encoding, or allowlist exists anywhere between the source and the sink, so the finding is exploitable as reported.

## Fix

### File: LoginFailureLogConcat.cs

```csharp
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace EvalCases.Cwe117;

[ApiController]
[Route("account")]
public class AccountController : ControllerBase
{
    private static readonly Regex UnsafeLogChars = CreateUnsafeLogCharsRegex();

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

    // Encodes characters that could be used to forge or break out of a log entry
    // (CWE-117): the ASCII control range, DEL, the Unicode line/paragraph
    // separators, and the backslash itself, so an attacker-typed backslash-n
    // cannot be mistaken for a real newline once encoded.
    private static string SanitizeForLog(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value ?? string.Empty;
        }

        return UnsafeLogChars.Replace(value, m => (char)0x5C + "u" + ((int)m.Value[0]).ToString("x4"));
    }

    private static Regex CreateUnsafeLogCharsRegex()
    {
        var sb = new StringBuilder();
        for (var c = 0x00; c <= 0x1F; c++)
        {
            sb.Append((char)c);
        }

        sb.Append((char)0x7F);
        sb.Append((char)0x85);
        sb.Append((char)0x2028);
        sb.Append((char)0x2029);
        sb.Append((char)0x5C);

        return new Regex("[" + Regex.Escape(sb.ToString()) + "]");
    }
}
```

## Explanation

The fix closes the finding at the reported sink in two parts. First, the log call is switched from string interpolation to a parameterized message template (`"Failed login attempt for user: {Username}"` with `username` passed as a separate argument), which keeps the template and the value apart. Second - the part that actually neutralizes the payload - every value logged this way is run through `SanitizeForLog`, which replaces the ASCII control range (0x00-0x1F), DEL (0x7F), the Unicode line/paragraph separators (U+0085, U+2028, U+2029), and the backslash character itself with a `\uXXXX` textual escape of its code point. Escaping the backslash is what keeps the fix sound: without it, an attacker who types the two characters `\` and `n` would render identically to an escaped real newline, destroying the evidence that an injection was attempted. Characters are encoded, not stripped, so the log still shows that an attempt occurred. Ordinary usernames (letters, digits, punctuation, non-ASCII text) pass through `SanitizeForLog` unchanged, since none of their characters fall in the encoded set. `IsInvalidCredentials`'s always-`false` body was left untouched since it is unrelated to the logging sink.

**Verification**: The class was compiled standalone against `Microsoft.AspNetCore.Mvc`/`Microsoft.Extensions.Logging` (`Microsoft.NET.Sdk.Web`, target `net10.0`) with `dotnet build` - 0 warnings, 0 errors. `SanitizeForLog` was then exercised via reflection in a small test harness against the compiled assembly: a real newline character (code point 0x0A) encodes to the six-character text backslash-u-0-0-0-a; a literal two-character sequence backslash-n (backslash followed by the letter n) encodes the backslash to backslash-u-0-0-5-c and leaves the letter n alone, so it is textually distinct from the real-newline case as required; an ordinary username (`regular.user-name_123`) passes through unchanged; a `null` username returns `string.Empty` without throwing.

## Behaviour changes

- Log message changed from an interpolated string to a parameterized template (`{Username}` placeholder). No behavioral effect on the rendered text for a benign username - the formatted output is the same string that interpolation would have produced - but it enables the encoding-aware formatting path and satisfies Roslyn rule CA2254 (non-constant logging template). Required by the fix, not incidental.
- `username` is now passed through `SanitizeForLog` before logging: any character in the ASCII control range, DEL, the Unicode line/paragraph separators, or a literal backslash is rendered as a `\uXXXX` escape instead of appearing raw in the log line. This is the change that closes the weakness; it only affects log output, not the HTTP response, the `Unauthorized()` status code, or the credential check.
- A `null` `username` now logs as an empty string via the added null/empty guard, matching what string interpolation of a `null` argument already produced (interpolating `null` yields an empty substitution), so no observable change there.
- No change to `IsValidCredentials`, the `Unauthorized()`/`Ok()` return values, or the request-binding attributes.
