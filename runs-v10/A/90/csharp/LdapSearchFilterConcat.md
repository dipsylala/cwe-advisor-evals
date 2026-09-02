## Verdict

CONFIRMED. The `username` parameter is concatenated directly into an LDAP filter string without escaping, allowing attackers to inject LDAP syntax and modify the query logic.

## Source

Line 17 constructs the LDAP filter by concatenating user-supplied input:
```csharp
searcher.Filter = "(sAMAccountName=" + username + ")";
```

The `username` parameter originates from the query string (`[FromQuery] string username`) and flows directly into the filter without sanitization.

## Fix

Escape special LDAP filter characters before including the username in the filter:

```csharp
private static string EscapeLdapFilterValue(string value)
{
    return value
        .Replace("\\", "\\5c")
        .Replace("*", "\\2a")
        .Replace("(", "\\28")
        .Replace(")", "\\29")
        .Replace("\0", "\\00")
        .Replace("/", "\\2f");
}

// In FindUser method:
var escapedUsername = EscapeLdapFilterValue(username);
searcher.Filter = $"(sAMAccountName={escapedUsername})";
```

## Explanation

LDAP filter syntax uses characters like `*`, `(`, `)`, and `\` as operators. An unescaped input like `*)(|(uid=*` can break out of the intended filter structure and inject arbitrary logic—for example, converting `(sAMAccountName=*)(|(uid=*)` into a filter that matches all users.

The fix escapes these special characters using hexadecimal notation (`\XX`), converting them into literal values that the LDAP parser treats as data rather than syntax. This ensures that user input cannot modify the filter structure, only the value being searched.
