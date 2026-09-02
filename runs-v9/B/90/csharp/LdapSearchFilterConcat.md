## Verdict

Exploitable. CWE-90 (LDAP Injection), confirmed at `LdapSearchFilterConcat.cs:17`. Confidence: high.

## Source

`username`, the `[FromQuery]` parameter of `DirectoryLookupController.FindUser`, is attacker-controlled request input. It flows unvalidated and unescaped directly into the sink four lines later:

```
searcher.Filter = "(sAMAccountName=" + username + ")";
```

No validation, allowlist check, or escaping occurs anywhere between the source and the sink. A value such as `*)(objectClass=*` closes the `sAMAccountName` term early and appends an attacker-controlled clause, letting the query enumerate arbitrary directory entries instead of the single intended account.

Sink contract: `DirectorySearcher.Filter` is a plain string setter with no built-in escaping. The searcher is constructed against a fixed base `DirectoryEntry` and default `SearchScope`/`PropertiesToLoad`; the fix below touches none of that.

## Fix

No third-party library is required; the fix uses a regex allowlist on the untrusted input, per the CWE-90 C# guidance, before it reaches the filter string.

Vulnerable code:

```csharp
using System.DirectoryServices;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Ldap;

[ApiController]
[Route("api/directory")]
public class DirectoryLookupController : ControllerBase
{
    [HttpGet("users")]
    public IActionResult FindUser([FromQuery] string username)
    {
        using var entry = new DirectoryEntry("LDAP://dc=example,dc=com");
        using var searcher = new DirectorySearcher(entry);

        // VULNERABLE: untrusted `username` concatenated directly into the LDAP filter
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
    private static readonly Regex UsernamePattern = new("^[a-zA-Z0-9._-]{3,64}$", RegexOptions.Compiled);

    [HttpGet("users")]
    public IActionResult FindUser([FromQuery] string username)
    {
        if (username == null || !UsernamePattern.IsMatch(username))
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

`username` reaches `DirectorySearcher.Filter` with no neutralization, so any of the RFC 4515 filter metacharacters (`*`, `(`, `)`, `\`) it contains change the structure of the LDAP query rather than being treated as literal search data. The fix adds a strict allowlist check - `^[a-zA-Z0-9._-]{3,64}$`, matching the pattern this knowledge base's CWE-90 C# guidance gives for username-shaped input - and rejects any request whose `username` doesn't match before the value is ever used to build the filter. Because none of the allowlisted characters carry meaning in an LDAP filter, a value that passes validation cannot alter the filter's structure, closing the injection at its source rather than trying to sanitize it at the sink.

## Behaviour changes

- Added a validation branch that returns `400 Bad Request` for any `username` that is null or fails the `^[a-zA-Z0-9._-]{3,64}$` allowlist (empty, too long, or containing characters outside that set - including the LDAP metacharacters `*`, `(`, `)`, `\`, and any whitespace or non-ASCII characters). Previously such input reached the LDAP filter directly. This is the intended effect of the fix: legitimate `sAMAccountName` values are ASCII alphanumeric plus `._-` and fall within this pattern, so expected callers are unaffected, but a caller relying on a `username` outside that shape (e.g. containing a space) will now be rejected rather than silently mishandled.
- No other change: the base DN, search scope, loaded properties, filter template, `FindOne()` call, and response shape are all unchanged from the original.
