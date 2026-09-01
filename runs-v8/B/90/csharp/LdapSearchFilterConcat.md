## Verdict

**VULNERABLE** - CWE-90 LDAP Injection confirmed. The `username` parameter from the HTTP query string is directly concatenated into the LDAP filter at line 17 without validation or escaping, allowing an attacker to inject LDAP metacharacters and modify the query logic.

## Source

`username` parameter received via `[FromQuery]` attribute on line 11. This is untrusted user input from an HTTP request.

## Fix

Add strict allowlist validation before using the username in the LDAP filter:

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
    [HttpGet("users")]
    public IActionResult FindUser([FromQuery] string username)
    {
        // Validate username against allowlist pattern to prevent LDAP injection
        if (string.IsNullOrEmpty(username) || !Regex.IsMatch(username, @"^[a-zA-Z0-9._-]{3,64}$"))
        {
            return BadRequest("Invalid username format");
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

The fix adds regex-based allowlist validation that restricts the username to alphanumeric characters, periods, underscores, and hyphens, with a length between 3 and 64 characters. This pattern eliminates all LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) that could be used to inject or modify the LDAP query. The validation check is performed before the username is used in the filter, and invalid usernames return a 400 Bad Request response. Only usernames that pass the allowlist check proceed to the LDAP query, ensuring that the concatenated filter string cannot be manipulated by an attacker.

## Behaviour changes

- **New validation:** HTTP GET requests to `/api/directory/users` with invalid usernames (those not matching `^[a-zA-Z0-9._-]{3,64}$`) now receive a 400 Bad Request response instead of proceeding to the LDAP query.
- **Request rejection:** Usernames with LDAP metacharacters (`*`, `(`, `)`, `\`), spaces, or length outside 3–64 characters are rejected.
- **Successful request:** Requests with valid usernames proceed unchanged to the LDAP search and return the same 200/404/500 responses as before.
- **Security impact:** The injection point is eliminated; attackers cannot modify LDAP filter structure via the username parameter.
