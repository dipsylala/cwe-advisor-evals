## Verdict

Real vulnerability. Untrusted user input from the `username` query parameter is concatenated directly into the LDAP filter string without escaping, allowing injection of LDAP metacharacters.

## Source

Line 11: `[FromQuery] string username` - untrusted query parameter input
Line 17: `searcher.Filter = "(sAMAccountName=" + username + ")"` - direct concatenation into LDAP filter

An attacker can inject LDAP syntax by supplying special characters (`*`, `(`, `)`, `\`) in the username parameter. For example, `*` changes the filter to a presence test matching all entries, and `)` closes the current filter term, allowing additional filter expressions to be injected.

## Fix

Replace string concatenation with LDAP-safe escaping of the username parameter. Create a helper function to escape RFC 4515 special characters:

```csharp
private string EscapeLdapFilterValue(string value)
{
    if (value == null) return null;
    
    // RFC 4515 escaping: replace special characters with hex notation
    return value
        .Replace("\\", "\\5c")  // backslash first to avoid double-escaping
        .Replace("*", "\\2a")   // asterisk
        .Replace("(", "\\28")   // left paren
        .Replace(")", "\\29")   // right paren
        .Replace("\0", "\\00"); // null byte
}

[HttpGet("users")]
public IActionResult FindUser([FromQuery] string username)
{
    if (string.IsNullOrWhiteSpace(username))
    {
        return BadRequest("Username is required");
    }
    
    using var entry = new DirectoryEntry("LDAP://dc=example,dc=com");
    using var searcher = new DirectorySearcher(entry);

    // Escape the username to prevent LDAP injection
    string escapedUsername = EscapeLdapFilterValue(username);
    searcher.Filter = "(sAMAccountName=" + escapedUsername + ")";

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

The fix applies RFC 4515 LDAP filter value escaping, which replaces the five special characters that have syntactic meaning in LDAP filters: backslash, asterisk, left parenthesis, right parenthesis, and null byte. The backslash must be escaped first to avoid double-escaping the escape sequences inserted by subsequent replacements. This escaping separates the filter structure from the user data, so injected parentheses and wildcards are treated as literal characters rather than LDAP operators. The escaped value is then safe to interpolate into the filter string. Null/whitespace input validation is added to reject empty usernames before reaching the LDAP operation.

## Behaviour changes

- Input validation rejects empty usernames with a 400 response before any LDAP operation (new behavior)
- Special characters in valid usernames (e.g., usernames containing `*` or `(`) are escaped and treated literally, not as LDAP syntax
- Filter behavior unchanged for usernames containing only alphanumeric characters and other non-special characters
- `DirectorySearcher.FindOne()` and result handling remain unchanged
