## Verdict

CWE-117 (Improper Output Neutralization for Logs) - **exploitable**. Confidence: high.

## Source

`username`, an `[FromForm] string` parameter on `AccountController.Login` (`POST /account/login`). This is attacker-controlled HTTP form data with no validation, length limit, or character restriction applied before it reaches the log call - `IsValidCredentials` only returns a boolean and never touches or constrains the value itself.

## Fix

Vulnerable code (`LoginFailureLogConcat.cs`, line 23):

```csharp
[HttpPost("login")]
public IActionResult Login([FromForm] string username, [FromForm] string password)
{
    if (!IsValidCredentials(username, password))
    {
        // VULNERABLE: untrusted input interpolated directly into the log message,
        // letting CR/LF or other control characters forge additional log entries.
        _logger.LogWarning($"Failed login attempt for user: {username}");
        return Unauthorized();
    }

    return Ok();
}
```

Fixed code:

```csharp
using System.Text;

// ...

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

private static string SanitizeForLog(string value)
{
    if (string.IsNullOrEmpty(value))
    {
        return value;
    }

    var sb = new StringBuilder(value.Length);
    foreach (var c in value)
    {
        switch (c)
        {
            case '\\':
                sb.Append("\\\\");
                break;
            case '\u0085':
                sb.Append("\\u0085");
                break;
            case '\u2028':
                sb.Append("\\u2028");
                break;
            case '\u2029':
                sb.Append("\\u2029");
                break;
            default:
                if (c <= '\x1F' || c == '\x7F')
                {
                    sb.Append("\\x").Append(((int)c).ToString("X2"));
                }
                else
                {
                    sb.Append(c);
                }
                break;
        }
    }

    return sb.ToString();
}
```

## Explanation

The original code built the log message by string interpolation, so any CR/LF, other ASCII control character, or Unicode line separator in `username` was written to the log verbatim - an attacker submitting a username like `bob%0d%0aFailed login attempt for user: admin` (decoded to real CR/LF by ASP.NET Core's form binder before this code ever sees it) could forge a second, fabricated log line indistinguishable from a real entry. The fix does two things, matching the C# guidance's distinction between them: it switches the call to a parameterized message template (`"...{Username}", value`) so the template and the value are no longer spliced into one string - this alone does not neutralize anything, since the guidance is explicit that Serilog's own JSON formatters (`JsonFormatter`, `CompactJsonFormatter`) only escape ASCII controls plus `"`/`\` and do not extend to DEL or the Unicode separators, and the application's actual logging provider/formatter isn't known from this file. `SanitizeForLog` therefore encodes the full range the entry calls for - ASCII control characters 0x00-0x1F, DEL (0x7F), U+0085, U+2028, U+2029, and the backslash itself (escaped first, and before the other replacements are appended, so a literal `\` produces `\\` rather than colliding with an escape sequence produced by a later branch) - characters are encoded, not stripped, so an injection attempt still appears in the log as evidence rather than being silently discarded. This closes the finding regardless of which formatter or sink the application is ultimately configured with.

## Behaviour changes

- The value logged for `username` changes whenever it contains a control character, U+0085/U+2028/U+2029, or a backslash: those characters are now rendered as escape sequences (e.g. `\x0A`, `\u2028`, `\\`) instead of appearing literally. This is the intended effect of the fix, not incidental - it is what prevents log-entry forgery. Ordinary usernames (letters, digits, punctuation, non-ASCII text without those specific code points) are logged unchanged.
- The logger call changes from string interpolation to a parameterized template (`LogWarning("...{Username}", value)`), matching the guidance's Roslyn CA2254 guidance for non-constant templates. This does not alter what is written to the default text output but keeps the value available as a structured field if the application later moves to structured/JSON logging.
- No other arguments, return values, control flow, or the `IsValidCredentials` / `Unauthorized()` behaviour were changed.

**Assumption**: the application's configured logging provider/formatter (console text, Serilog JSON, etc.) is not visible from this single file, so the fix does not rely on any formatter already encoding these characters, per the C# guidance's explicit warning not to assume a JSON sink already covers this range.
