## Verdict

exploitable

## Source

The `username` parameter from `[FromQuery]` at line 11, which passes untrusted HTTP query string data directly to the LDAP filter sink without validation or escaping.

## Fix

### File: LdapSearchFilterConcat.cs

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
        // Validate username against strict allowlist pattern per CWE-90 remediation
        if (string.IsNullOrEmpty(username) || !Regex.IsMatch(username, @"^[a-zA-Z0-9._-]{3,64}$"))
        {
            return BadRequest("Invalid username format");
        }

        using var entry = new DirectoryEntry("LDAP://dc=example,dc=com");
        using var searcher = new DirectorySearcher(entry);

        // Safe: username has been validated and contains no LDAP metacharacters
        searcher.Filter = "(sAMAccountName=" + username + ")";

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

The vulnerability in the original code was that the `username` query parameter was directly concatenated into the LDAP filter string without any validation or escaping. An attacker could inject LDAP metacharacters—specifically `*`, `(`, `)`, `\`, or NUL—to alter the query structure and bypass authorization checks. For example, injecting `*` would turn an equality test into a wildcard match that returns all entries.

The fix adds strict allowlist validation using `Regex.IsMatch()` with the pattern `^[a-zA-Z0-9._-]{3,64}$` before the username is used in the filter. This pattern restricts usernames to alphanumeric characters, dots, underscores, and hyphens—none of which are LDAP filter metacharacters. The validation is applied before any LDAP operations, and invalid usernames are rejected with a BadRequest response. The validated username is then safe to use in the filter string because it provably contains no characters that could modify the query structure.

## Behaviour changes

1. **Input validation rejection** - The method now returns HTTP 400 (BadRequest) for usernames that do not match the allowlist pattern or are empty. The original code accepted any string. This is a security-critical change and required behaviour.
2. **Added import** - `System.Text.RegularExpressions` added for `Regex.IsMatch()`. This is a standard library import with no security implications.
3. **Response code change** - Invalid requests now receive 400 instead of attempting the LDAP query. This is correct behaviour and prevents the query from being executed with malicious input.

No other behaviour changes. The valid path (matching username and successful LDAP search) produces the same output as before.

## Verification

Syntax verification: `dotnet build` was run against the fixed code with Microsoft.AspNetCore.Mvc and System.DirectoryServices dependencies. The code compiled without errors. Platform-specific warnings (CA1416) for Windows-only APIs are expected and present in both original and fixed code; they do not indicate code defects.

All API calls verified:
- `Regex.IsMatch(string, string)` - standard library method from System.Text.RegularExpressions
- `string.IsNullOrEmpty(string)` - standard library method
- `DirectoryEntry` and `DirectorySearcher` - from System.DirectoryServices (verified in dependency)
- `DirectorySearcher.Filter` property assignment - valid API
- `FindOne()`, `NotFound()`, `BadRequest()`, `Ok()` - all standard MVC methods

## Assumptions

- The allowlist pattern `^[a-zA-Z0-9._-]{3,64}$` is appropriate for valid sAMAccountName values in this system. An actual deployment should verify this against the directory service's username policy.
- The LDAP bind account has appropriate permissions to perform searches. The fix does not change the permission model, only the input validation.
- Platform target is Windows/.NET Framework or .NET 5+, as System.DirectoryServices is Windows-only.
