## Verdict
Real vulnerability confirmed.

## Source
`username` parameter from HTTP query string at line 11: `[FromQuery] string username`. Untrusted user input.

## Fix
Apply strict allowlist validation to the username before constructing the LDAP filter. For a typical sAMAccountName, restrict to alphanumeric characters, dots, hyphens, and underscores:

```csharp
using System.DirectoryServices;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Ldap;

[ApiController]
[Route("api/directory")]
public class DirectoryLookupController : ControllerBase
{
    [HttpGet("users")]
    public IActionResult FindUser([FromQuery] string username)
    {
        // Validate username against allowlist - restrict to expected sAMAccountName pattern
        if (string.IsNullOrWhiteSpace(username) || !Regex.IsMatch(username, @"^[a-zA-Z0-9._\-]{3,64}$"))
        {
            return BadRequest("Invalid username format");
        }

        using var entry = new DirectoryEntry("LDAP://dc=example,dc=com");
        using var searcher = new DirectorySearcher(entry);

        // Use validated username - now safe from LDAP injection
        searcher.Filter = "(sAMAccountName=" + username + ")";

        var result = searcher.FindOne();
        if (result == null)
        {
            return NotFound();
        }

        return Ok(new
        {
            result.Properties["displayName"],
            result.Properties["mail"]
        });
    }
}
```

**Alternative: Manual RFC 4515 Escaping** (if allowlist cannot be applied)

If usernames cannot be restricted to an allowlist pattern, escape LDAP metacharacters using RFC 4515 hex encoding:

```csharp
private static string EscapeLdapFilterValue(string input)
{
    if (string.IsNullOrEmpty(input))
        return input;

    var sb = new System.Text.StringBuilder();
    foreach (char c in input)
    {
        switch (c)
        {
            case '\\': sb.Append("\\5c"); break;  // Backslash
            case '*': sb.Append("\\2a"); break;   // Asterisk
            case '(': sb.Append("\\28"); break;   // Left paren
            case ')': sb.Append("\\29"); break;   // Right paren
            case '\0': sb.Append("\\00"); break;  // NUL
            default: sb.Append(c); break;
        }
    }
    return sb.ToString();
}

// Then use escaped value:
searcher.Filter = "(sAMAccountName=" + EscapeLdapFilterValue(username) + ")";
```

## Explanation
The fix closes the LDAP injection by preventing untrusted input from altering the LDAP filter structure. The allowlist approach (preferred) restricts usernames to a safe character set that cannot contain LDAP metacharacters, eliminating the injection point entirely. The escaping alternative encodes the five special characters that RFC 4515 gives meaning to in LDAP filters (`*`, `(`, `)`, `\`, NUL) into their hex-escaped forms, which the LDAP parser treats as literal characters rather than syntax.

The validated/escaped username is then safe to concatenate into the filter string at line 17. The rest of the code flow (filter construction, search execution, property access) remains unchanged.

## Behaviour changes
- Username input is now validated; requests with invalid usernames return HTTP 400 (Bad Request) instead of proceeding to the LDAP search
- LDAP filter injection attempts are blocked: injected `*`, `(`, `)`, etc. are either rejected by validation or escaped to literal characters
- Legitimate searches for usernames matching the expected pattern proceed unchanged
