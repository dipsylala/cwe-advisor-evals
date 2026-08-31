## Verdict
VULNERABLE: Line 17 constructs an LDAP filter by concatenating an untrusted query parameter directly into the filter string without escaping special LDAP characters. An attacker can inject LDAP syntax (e.g., `*`, `()`, `\`) to modify query logic, bypass authentication, or extract unauthorized data.

## Source
The `username` parameter (line 11) originates from an HTTP query string with no validation or encoding before reaching the filter construction.

## Fix
Escape special LDAP characters before concatenating them into the filter. Create an escape helper and apply it:

```csharp
using System;
using System.Text;
using System.DirectoryServices;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Ldap;

[ApiController]
[Route("api/directory")]
public class DirectoryLookupController : ControllerBase
{
    private static string EscapeLdapFilterValue(string value)
    {
        if (string.IsNullOrEmpty(value))
            return value;

        var sb = new StringBuilder();
        foreach (char c in value)
        {
            switch (c)
            {
                case '*':
                case '(':
                case ')':
                case '\\':
                case '\0':
                    sb.Append('\\').Append(c);
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

        searcher.Filter = "(sAMAccountName=" + EscapeLdapFilterValue(username) + ")";

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
LDAP filter syntax includes metacharacters (`*` for wildcard, `()` for grouping, `\` for escaping, null for termination) that change query meaning when unescaped. The fix escapes these five special characters by prefixing each with a backslash, neutralizing their syntactic interpretation and treating them as literal string data. This follows RFC 4515 LDAP filter escaping rules. The escaped value can now be safely concatenated into the filter string without risk of injection. Alternative approaches include using `System.DirectoryServices.AccountManagement` for higher-level APIs or validating input against a strict allowlist of permitted characters.
