## Verdict

Exploitable. The `username` query parameter (source) is directly concatenated into the LDAP filter without validation or escaping (sink at line 17). An attacker can inject LDAP metacharacters (`*`, `(`, `)`, `\`) to modify the filter logic and bypass intended query constraints.

## Source

`username` parameter from `[FromQuery] string username` on line 11. Attacker-controlled input from HTTP query string.

## Fix

**Vulnerable code:**
```csharp
searcher.Filter = "(sAMAccountName=" + username + ")";
```

**Fixed code (with allowlist validation):**
```csharp
using System.Text.RegularExpressions;

[HttpGet("users")]
public IActionResult FindUser([FromQuery] string username)
{
    // Validate username against strict allowlist pattern
    if (string.IsNullOrWhiteSpace(username) || !Regex.IsMatch(username, @"^[a-zA-Z0-9._-]{3,64}$"))
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
```

**Alternative fix (with RFC 4515 escaping, if allowlist is not feasible):**
```csharp
private string EscapeLdapFilterValue(string input)
{
    if (string.IsNullOrEmpty(input))
        return input;
    
    return input
        .Replace("\\", "\\5c")  // Backslash - must be first
        .Replace("*", "\\2a")   // Asterisk
        .Replace("(", "\\28")   // Left parenthesis
        .Replace(")", "\\29")   // Right parenthesis
        .Replace("\0", "\\00"); // Null character
}

// In the action method:
var escapedUsername = EscapeLdapFilterValue(username);
searcher.Filter = "(sAMAccountName=" + escapedUsername + ")";
```

## Explanation

The vulnerability occurs because user input is directly concatenated into an LDAP filter string. LDAP filter syntax uses special characters (`*`, `(`, `)`, `\`) to express query logic. An attacker can inject these characters to modify the filter's meaning—for example, `admin*)(&` terminates the current filter clause and opens a new one, or `*` converts an equality check to a wildcard match-all.

The recommended fix uses strict allowlist validation with the regex `^[a-zA-Z0-9._-]{3,64}$` before any LDAP operations. This rejects input containing special characters and returns a `BadRequest` response. Because the validated username contains only alphanumeric, dot, underscore, and hyphen characters, it cannot contain LDAP metacharacters and is safe to use in the filter.

If allowlist validation is not practical for your use case, RFC 4515 escaping provides defense-in-depth: replacing the five LDAP metacharacters with their hex escape forms (`\2a`, `\28`, `\29`, `\5c`, `\00`) neutralizes them. Important: backslash must be escaped first, or subsequent escape sequences are escaped a second time. Note that DN escaping (RFC 4514) uses a different character set; never reuse filter escaping for DN construction.

## Behaviour changes

- Added input validation before LDAP search: invalid usernames now return HTTP 400 `BadRequest` instead of proceeding to search. This changes the error handling path and may cause different behavior for malformed input, but closes the injection vector.
- No change to successful-search behavior: valid usernames produce the same LDAP filter and directory lookup as before.
- No change to null/not-found handling: searches returning no results still return HTTP 404 `NotFound`.
