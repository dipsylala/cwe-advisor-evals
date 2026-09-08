## Verdict

Exploitable - the `username` parameter flows directly from a user-controlled HTTP query parameter into the LDAP filter string without escaping, allowing injection of LDAP syntax characters.

## Source

The `username` parameter from `[FromQuery] string username` in the `FindUser` method (line 11). This is attacker-controlled input from an HTTP query string.

## Fix

### File: LdapSearchFilterConcat.cs

```csharp
using System.DirectoryServices;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Ldap;

[ApiController]
[Route("api/directory")]
public class DirectoryLookupController : ControllerBase
{
    // Helper method to escape LDAP filter metacharacters per RFC 4515
    private static string EscapeLdapFilter(string input)
    {
        if (input == null)
            return null;
        
        // Replace backslash first to avoid double-escaping the sequences we insert
        return input
            .Replace("\\", "\\5c")
            .Replace("*", "\\2a")
            .Replace("(", "\\28")
            .Replace(")", "\\29")
            .Replace("\0", "\\00");
    }

    [HttpGet("users")]
    public IActionResult FindUser([FromQuery] string username)
    {
        using var entry = new DirectoryEntry("LDAP://dc=example,dc=com");
        using var searcher = new DirectorySearcher(entry);

        // Escape the username to prevent LDAP injection
        string escapedUsername = EscapeLdapFilter(username);
        searcher.Filter = "(sAMAccountName=" + escapedUsername + ")";

        var result = searcher.FindOne();
        if (result == null)
        {
            return NotFound();
        }

        return Ok(new
        {
            displayName = result.Properties["displayName"],
            mail = result.Properties["mail"]
        });
    }
}
```

## Explanation

The fix adds an `EscapeLdapFilter` helper method that escapes LDAP filter metacharacters per RFC 4515. The method replaces backslash (`\`) first to avoid double-escaping the escape sequences it then inserts, then replaces each of the five metacharacters defined by RFC 4515: `*` → `\2a`, `(` → `\28`, `)` → `\29`, `\` → `\5c`, and NUL → `\00`. The escaped username is then used in the filter construction instead of the raw input. This prevents an attacker from injecting LDAP syntax characters that would alter the filter's meaning. For example, a payload like `admin*)(&(uid=*` would no longer close the current clause and open a new one, but would instead be treated as a literal string to match.

## Behaviour changes

None. The escaped filter maintains the same functional contract as the original: it searches for an exact sAMAccountName value (now with metacharacters escaped but semantically equivalent), returns the same `SearchResult` object or null on no match, and the calling code processes the result identically. The function signature, return type, error handling, and API response format are unchanged; only the intermediate filter value is sanitized. The `DirectorySearcher.Filter` property still receives a valid LDAP filter string per RFC 4515, and the search semantics are preserved.
