## Verdict

Exploitable.

## Source

`username` parameter from HTTP query string: `[FromQuery] string username` (line 11). Input is user-controlled and flows directly into the LDAP filter without validation or escaping.

## Fix

Vulnerable code (line 17):
```csharp
searcher.Filter = "(sAMAccountName=" + username + ")";
```

Fixed code:
```csharp
using System.Text.RegularExpressions;

[HttpGet("users")]
public IActionResult FindUser([FromQuery] string username)
{
    // Validate input against allowlist before using in LDAP filter
    if (!Regex.IsMatch(username, @"^[a-zA-Z0-9._-]{3,64}$"))
    {
        return BadRequest("Invalid username format");
    }
    
    using var entry = new DirectoryEntry("LDAP://dc=example,dc=com");
    using var searcher = new DirectorySearcher(entry);

    // Safe: Filter constructed with validated input only
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
```

## Explanation

The fix adds input validation using a regex allowlist that restricts usernames to alphanumeric characters, dots, underscores, and hyphens (3-64 characters), following the pattern specified in the C# CWE-90 guidance. This prevents injection of LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) that could manipulate the filter logic. Invalid usernames are rejected with a BadRequest response before reaching the LDAP filter construction. Only validated input flows into the filter, eliminating the injection vector.

## Behaviour changes

- Adds `System.Text.RegularExpressions` import (standard .NET library, always available)
- Adds regex validation before LDAP operations; usernames not matching the allowlist are rejected with HTTP 400
- The DirectorySearcher.Filter assignment remains unchanged in structure; it now receives only validated input
- HTTP clients sending invalid usernames receive a BadRequest (400) response instead of proceeding to LDAP query
