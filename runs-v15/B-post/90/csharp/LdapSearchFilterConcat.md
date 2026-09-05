## Verdict
Exploitable

## Source
Untrusted `username` parameter from HTTP query string (`[FromQuery] string username` at line 11) flows directly into LDAP filter construction without validation or escaping.

## Fix

**Vulnerable code:**
```csharp
[HttpGet("users")]
public IActionResult FindUser([FromQuery] string username)
{
    using var entry = new DirectoryEntry("LDAP://dc=example,dc=com");
    using var searcher = new DirectorySearcher(entry);

    searcher.Filter = "(sAMAccountName=" + username + ")";  // VULNERABLE: direct concatenation

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
```

**Fixed code:**
```csharp
using System.Text.RegularExpressions;
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
        // Apply strict allowlist validation - only alphanumeric, dots, dashes, underscores
        if (string.IsNullOrEmpty(username) || !Regex.IsMatch(username, @"^[a-zA-Z0-9._-]{3,64}$"))
        {
            return BadRequest("Invalid username format");
        }

        using var entry = new DirectoryEntry("LDAP://dc=example,dc=com");
        using var searcher = new DirectorySearcher(entry);

        // Safe to use - validated against allowlist before reaching filter
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
The fix applies a strict allowlist validation using a regex pattern (`^[a-zA-Z0-9._-]{3,64}$`) to restrict the username to expected safe characters before it is concatenated into the LDAP filter string. This prevents an attacker from injecting LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) that could modify the filter structure and bypass authentication or access unauthorized directory entries. The validation returns `BadRequest` if the input does not conform, rejecting any attempt to supply filter injection payloads. This approach follows the RFC 4515 principle of separating query structure from user data—here by enforcing that user data conforms to a safe character set before it appears in the filter.

## Behaviour changes
- The method now validates the `username` parameter against an allowlist pattern and returns HTTP 400 (`BadRequest`) if validation fails. Previously, any input was accepted and used directly in the filter.
- The method adds the `System.Text.RegularExpressions` using statement to support the `Regex.IsMatch()` call.
- No changes to successful-case behavior: when validation passes, the filter construction, search, and response are identical to the original.
