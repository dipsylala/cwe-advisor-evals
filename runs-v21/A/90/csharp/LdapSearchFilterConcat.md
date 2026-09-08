## Verdict

Fixed. The vulnerability on line 17 allows LDAP injection through unescaped user input concatenated directly into an LDAP filter string. The fix escapes special LDAP filter characters in the username before constructing the filter.

## Source

The vulnerable code at line 17 directly concatenates user input into an LDAP filter:

```csharp
searcher.Filter = "(sAMAccountName=" + username + ")";
```

LDAP filter syntax includes special characters (`*`, `(`, `)`, `\`, NUL) that have query significance. An attacker can inject these characters to bypass authentication or exfiltrate data. For example, a username of `*` would match any user, and `*))(&(uid=*)` could rewrite the filter logic.

## Fix

### File: LdapSearchFilterConcat.cs

```csharp
using System;
using System.DirectoryServices;
using System.Text;
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

        // Escape LDAP filter special characters to prevent LDAP injection
        searcher.Filter = "(sAMAccountName=" + EscapeLdapFilterValue(username) + ")";

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

    private static string EscapeLdapFilterValue(string value)
    {
        if (value == null)
            return null;

        var sb = new StringBuilder();
        foreach (char c in value)
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
}
```

## Explanation

The fix adds an `EscapeLdapFilterValue()` method that escapes LDAP filter special characters according to RFC 4515. Each dangerous character is replaced with its hex-encoded escape sequence:
- `*` becomes `\2a` (prevents wildcards)
- `(` becomes `\28` (prevents filter nesting)
- `)` becomes `\29` (prevents filter nesting)
- `\` becomes `\5c` (prevents escape-sequence injection)
- NUL becomes `\00` (prevents null-byte injection)

Legitimate usernames (alphanumerics, dots, hyphens, underscores) pass through unchanged. This approach preserves the original query intent while neutralizing injection attempts. Any user input containing special characters is now safe to include in an LDAP filter string.

