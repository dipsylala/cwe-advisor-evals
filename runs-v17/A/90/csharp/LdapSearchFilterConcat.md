## Verdict

Confirmed. The code directly concatenates untrusted user input from the `username` parameter into an LDAP filter string without escaping, enabling attackers to inject LDAP metacharacters and modify query logic.

## Source

```csharp
searcher.Filter = "(sAMAccountName=" + username + ")";
```

An attacker passing `username = "*"` would transform the filter to `(sAMAccountName=*)`, matching all users. Passing `username = "*)(&"` allows a logical OR injection to bypass authentication logic.

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
    /// <summary>
    /// Escapes special characters in LDAP filter values per RFC 4515.
    /// Replaces *, (, ), \, and null with \XX hex-encoded equivalents.
    /// </summary>
    private static string EscapeLdapFilterValue(string value)
    {
        if (string.IsNullOrEmpty(value))
            return value;

        var sb = new StringBuilder();
        foreach (char c in value)
        {
            switch (c)
            {
                case '\\':
                case '*':
                case '(':
                case ')':
                case '\0':
                    sb.AppendFormat("\\{0:X2}", (int)c);
                    break;
                default:
                    sb.Append(c);
                    break;
            }
        }
        return sb.ToString();
    }

    [HttpGet("users")]
    public IActionResult FindUser([FromQuery] string username)
    {
        using var entry = new DirectoryEntry("LDAP://dc=example,dc=com");
        using var searcher = new DirectorySearcher(entry);

        // Escape username to prevent LDAP injection
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
}
```

## Explanation

LDAP filter syntax treats `*`, `(`, `)`, `\`, and null as metacharacters. The vulnerability arises because `username` is concatenated directly without neutralizing these characters. An attacker can inject filter syntax to alter query logic—for example, `username = "*)(&` transforms the intended `(sAMAccountName=...)` into `(sAMAccountName=*)(&`, which changes the semantics.

The fix implements RFC 4515–compliant LDAP filter escaping: each metacharacter is replaced with a backslash followed by its two-digit ASCII hex code. The escaped value is then safe to concatenate. For example, `username = "*"` becomes the literal string `\2A`, which the LDAP server interprets as the character `*` rather than the wildcard operator.

The escaping function is placed inline in the controller to keep the remediation localized and verifiable; in production, it could be extracted to a utility class for reuse across multiple queries.
