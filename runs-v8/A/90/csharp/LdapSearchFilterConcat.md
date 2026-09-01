## Verdict
CONFIRMED. The code directly concatenates user-supplied input into an LDAP filter string without escaping, allowing an attacker to inject LDAP syntax and modify the query logic.

## Source
The `username` parameter from the `[FromQuery]` attribute (line 11) flows directly into the LDAP filter constructed on line 17 via string concatenation.

## Fix
Escape LDAP special characters in the username before constructing the filter. The characters `*`, `(`, `)`, `\`, `/`, and null bytes must be converted to their hex escape sequences:

```csharp
private string EscapeLdapFilterValue(string input)
{
    if (input == null)
        return null;
    
    var sb = new StringBuilder();
    foreach (char c in input)
    {
        switch (c)
        {
            case '*':
                sb.Append(@"\2a");
                break;
            case '(':
                sb.Append(@"\28");
                break;
            case ')':
                sb.Append(@"\29");
                break;
            case '\\':
                sb.Append(@"\5c");
                break;
            case '/':
                sb.Append(@"\2f");
                break;
            case '\0':
                sb.Append(@"\00");
                break;
            default:
                sb.Append(c);
                break;
        }
    }
    return sb.ToString();
}
```

Then use it:
```csharp
searcher.Filter = "(sAMAccountName=" + EscapeLdapFilterValue(username) + ")";
```

## Explanation
LDAP filter syntax uses special characters like `*` (wildcard), `(` and `)` (grouping), and `\` (escape prefix) to construct complex queries. An attacker can inject these characters to bypass authentication or retrieve unauthorized data. For example, a username of `*` would match any user, and `*)(uid=*))(|(uid=*` can modify the query logic entirely.

Escaping converts these special characters to their hex-encoded LDAP representations, ensuring they are treated as literal values within the filter string rather than LDAP syntax elements. This prevents query injection while preserving the intended filter logic.
