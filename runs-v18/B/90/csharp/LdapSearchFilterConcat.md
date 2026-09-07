## Verdict

Exploitable. The `username` parameter is untrusted user input from a query string that flows directly through string concatenation into `searcher.Filter` without escaping, allowing LDAP metacharacters to escape the intended filter expression.

## Source

`username` parameter on line 11, received from `[FromQuery] string username` - untrusted user input from the HTTP query string.

## Fix

### File: LdapSearchFilterConcat.cs

```csharp
using System;
using System.DirectoryServices;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Ldap;

[ApiController]
[Route("api/directory")]
public class DirectoryLookupController : ControllerBase
{
    private static string EscapeLdapFilterValue(string value)
    {
        if (value == null)
            return null;

        var result = new System.Text.StringBuilder();
        foreach (char c in value)
        {
            switch (c)
            {
                case '*':
                    result.Append("\\2a");
                    break;
                case '(':
                    result.Append("\\28");
                    break;
                case ')':
                    result.Append("\\29");
                    break;
                case '\\':
                    result.Append("\\5c");
                    break;
                case '\0':
                    result.Append("\\00");
                    break;
                default:
                    result.Append(c);
                    break;
            }
        }
        return result.ToString();
    }

    [HttpGet("users")]
    public IActionResult FindUser([FromQuery] string username)
    {
        using var entry = new DirectoryEntry("LDAP://dc=example,dc=com");
        using var searcher = new DirectorySearcher(entry);

        string escapedUsername = EscapeLdapFilterValue(username);
        searcher.Filter = "(sAMAccountName=" + escapedUsername + ")";

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

The fix adds RFC 4515 LDAP filter value escaping via the `EscapeLdapFilterValue()` helper method, which converts the special LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) into their hex-escaped forms (`\2a`, `\28`, `\29`, `\5c`, `\00`) before the value is incorporated into the filter string. This prevents attackers from escaping the filter expression using characters like `*` (to create a wildcard presence match) or `)` followed by `(` (to break out and inject additional filter terms). The escaped value is then safe to use in string concatenation because the metacharacters are no longer syntactically meaningful to the LDAP parser - they become literal characters within the `sAMAccountName` value being searched.

## Behaviour changes

- Added `EscapeLdapFilterValue()` helper method to perform RFC 4515 escaping. This is a new method with no prior behavior to preserve.
- The filter construction now processes the username through escaping before concatenation. The filter still performs the same attribute search but with the injected syntax neutralized. The sink contract (`searcher.Filter` assignment and subsequent `FindOne()` call) remains intact - the method still searches by `sAMAccountName` and returns the same result structure.
- No other code paths, return values, or side effects are altered.
