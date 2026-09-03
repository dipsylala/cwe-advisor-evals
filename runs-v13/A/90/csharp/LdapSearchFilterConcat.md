## Verdict

**CONFIRMED** – LDAP Injection vulnerability. The username parameter is concatenated directly into the LDAP filter string without escaping, allowing an attacker to inject LDAP metacharacters (*, (, ), \, /, null) to modify the filter logic or bypass authentication.

## Source

```csharp
searcher.Filter = "(sAMAccountName=" + username + ")";
```

## Fix

```csharp
searcher.Filter = "(sAMAccountName=" + EscapeLdapFilterString(username) + ")";

private static string EscapeLdapFilterString(string input)
{
    if (string.IsNullOrEmpty(input))
        return input;

    var sb = new StringBuilder();
    foreach (char c in input)
    {
        switch (c)
        {
            case '*':
                sb.Append("\\2a");
                break;
            case '(':
                sb.Append("\\28");
                break;
            case ')':
                sb.Append("\\29");
                break;
            case '\\':
                sb.Append("\\5c");
                break;
            case '/':
                sb.Append("\\2f");
                break;
            case '\0':
                sb.Append("\\00");
                break;
            default:
                sb.Append(c);
                break;
        }
    }
    return sb.ToString();
}
```

Add `using System.Text;` to the imports.

## Explanation

LDAP filter strings have special metacharacters that alter query logic. An attacker can inject characters like `*` (wildcard), `(` and `)` (grouping), or `\` (escape) to transform the filter. For example, injecting `*))(&(|(` could bypass intended filtering.

The fix escapes LDAP filter special characters per RFC 4515 before inclusion in the filter string. Each dangerous character is replaced with its hex-encoded representation: `*` → `\2a`, `(` → `\28`, `)` → `\29`, `\` → `\5c`, `/` → `\2f`, null → `\00`. This ensures user input is treated as literal data rather than filter syntax, preventing injection attacks.
