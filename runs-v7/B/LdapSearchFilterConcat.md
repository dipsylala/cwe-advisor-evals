## Verdict
Confirmed. The `username` query parameter flows unvalidated into `DirectorySearcher.Filter` through string concatenation, allowing LDAP metacharacter injection. An attacker can inject `*` to convert equality to wildcard matching, or `(` and `)` to close/open filter clauses and alter query logic.

## Source
`username` parameter from `[FromQuery]` on line 11 - untrusted HTTP query string input.

## Fix
Add regex allowlist validation before the LDAP operation. Restrict usernames to safe characters: alphanumeric, dot, underscore, hyphen, and length 3-64.

```csharp
using System;
using System.DirectoryServices;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Ldap;

[ApiController]
[Route("api/directory")]
public class DirectoryLookupController : ControllerBase
{
    private static readonly Regex ValidUsername = new Regex(@"^[a-zA-Z0-9._-]{3,64}$", RegexOptions.Compiled);

    [HttpGet("users")]
    public IActionResult FindUser([FromQuery] string username)
    {
        // Validate username against allowlist pattern per RFC 4515
        if (string.IsNullOrEmpty(username) || !ValidUsername.IsMatch(username))
        {
            return BadRequest("Invalid username format");
        }

        using var entry = new DirectoryEntry("LDAP://dc=example,dc=com");
        using var searcher = new DirectorySearcher(entry);

        // Safe: username is restricted to known-safe characters by validation above
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

## Explanation
The fix validates the username against a strict allowlist regex pattern (`^[a-zA-Z0-9._-]{3,64}$`) before it reaches the LDAP sink. Only usernames containing alphanumeric characters, dots, underscores, and hyphens (3-64 chars long) are accepted; all LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) and other dangerous characters are rejected at the gate. This prevents injection of filter syntax. The validation is applied early, at the entry point, following the guidance's preference for allowlist validation on sAMAccountName searches. The catch-all BadRequest response signals invalid input without exposing LDAP internals.

## Behaviour changes
- **Input rejection**: Usernames failing the regex pattern now return HTTP 400 (BadRequest) instead of being passed to LDAP search. This affects legitimate requests with non-standard usernames (spaces, special characters, excessive length).
- **LDAP query**: Remains unchanged for valid usernames; only safe characters are concatenated into the filter.
- **Error handling**: New validation error message returned to caller; LDAP-level errors (null result, search exceptions) remain unchanged.
- **Search scope**: Unchanged; query still searches the entire `dc=example,dc=com` base DN.
- **Returned data**: Unchanged when search succeeds; displayName and mail properties returned as before.
