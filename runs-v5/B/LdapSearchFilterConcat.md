## Verdict

Exploitable. CWE-90 (LDAP Injection), confidence: high.

## Source

`username`, bound from the query string via `[FromQuery] string username` on `DirectoryLookupController.FindUser` (`LdapSearchFilterConcat.cs:11`). It reaches the sink unvalidated and unescaped, three lines later, with no intermediate transformation.

## Fix

Vulnerable code (`LdapSearchFilterConcat.cs:17`):

```csharp
// SAST FINDING: CWE-90 (Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')) reported here. Sink is the next statement.
searcher.Filter = "(sAMAccountName=" + username + ")";
```

Fixed code:

```csharp
using System.DirectoryServices;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Ldap;

[ApiController]
[Route("api/directory")]
public class DirectoryLookupController : ControllerBase
{
    private static readonly Regex ValidUsername = new(@"^[a-zA-Z0-9._-]{3,64}$", RegexOptions.Compiled);

    [HttpGet("users")]
    public IActionResult FindUser([FromQuery] string username)
    {
        if (string.IsNullOrEmpty(username) || !ValidUsername.IsMatch(username))
        {
            return BadRequest("Invalid username.");
        }

        using var entry = new DirectoryEntry("LDAP://dc=example,dc=com");
        using var searcher = new DirectorySearcher(entry);

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

`username` was concatenated directly into the LDAP search filter, so any value containing `*`, `(`, `)`, or `\` could alter the filter's structure - closing the `sAMAccountName` clause early, opening a new one, or turning the equality test into a wildcard match against the whole directory. The fix applies the strict allowlist validation the C# guidance gives for this sink: a `^[a-zA-Z0-9._-]{3,64}$` regex, checked before the filter is built. Every character RFC 4515 gives meaning to in a filter falls outside that character class, so a request that would inject filter syntax is rejected with a 400 before it ever reaches `DirectorySearcher.Filter`, rather than being escaped and passed through. This matches the "validation isn't feasible - then escape" ordering in the guidance: for a username field, allowlist validation is feasible and is the primary control, so no separate escaping step is layered on top.

## Behaviour changes

- A request whose `username` is empty, shorter than 3 characters, longer than 64, or contains any character outside `[a-zA-Z0-9._-]` now returns `400 Bad Request` instead of reaching the directory search. This narrows the accepted input space; it is the intended effect of the fix and matches the guidance's recommended constraint for this field, but any legitimate username format outside that pattern (e.g. containing a space or an `@` for a UPN-style login) would now be rejected and should be confirmed against the real account-naming policy before deployment.
- No other change: the sink's contract is otherwise untouched. `DirectorySearcher.Filter` still receives `"(sAMAccountName=" + username + ")"` for any input that passes validation, `FindOne()`'s return value and the `NotFound()` / `Ok(...)` branching are unchanged, and the search scope, base DN, and returned properties (`displayName`, `mail`) are unmodified.
