## Verdict
Confirmed. `username` from `[FromQuery]` reaches `DirectorySearcher.Filter` via raw string concatenation, letting an attacker inject LDAP search filter metacharacters.

## Source
`FindUser([FromQuery] string username)` — `username` is attacker-controlled, taken directly from the query string with no validation or encoding.

## Fix
```csharp
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

        searcher.Filter = $"(sAMAccountName={EscapeLdapFilterValue(username)})";

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

    private static string EscapeLdapFilterValue(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            switch (c)
            {
                case '\\':
                    sb.Append("\\5c");
                    break;
                case '*':
                    sb.Append("\\2a");
                    break;
                case '(':
                    sb.Append("\\28");
                    break;
                case ')':
                    sb.Append("\\29");
                    break;
                case '\0':
                    sb.Append("\\00");
                    break;
                case '/':
                    sb.Append("\\2f");
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
`DirectorySearcher.Filter` is a raw LDAP search filter string (RFC 4515 syntax). Concatenating `username` into it lets an attacker close the intended clause early using `)`, `(`, and `*`, and append arbitrary additional filter terms — for example supplying `*)(objectClass=*` turns the filter into a wildcard match against every directory object, or `admin)(|(objectClass=*` can be used to bypass the intended single-user lookup and pull back other accounts' `displayName`/`mail` attributes.

`System.DirectoryServices` has no built-in filter-value encoder, so the fix escapes the RFC 4515 special characters by hand before interpolating the value: backslash, `*`, `(`, `)`, and NUL are replaced with their `\XX` hex-escaped forms, which LDAP servers decode back to the literal character rather than treating them as filter syntax. `/` is also escaped because `System.DirectoryServices` uses the `LDAP://` ADsPath scheme internally and some providers treat it specially in bound paths; escaping it here is defense in depth and does not change matching semantics for typical account name values.

This escapes filter *values*, not distinguished names (DN) — if `username` were ever used to build or bind to a DN (e.g., `CN=...,DC=...`) a separate DN-escaping routine would be needed, since DN and filter escaping rules differ. Only filter-value escaping is required here because the sink is `DirectorySearcher.Filter`.

After the fix, verify that a value such as `*` alone no longer returns every user, that a value containing `)(uid=*` no longer expands the filter, and that legitimate usernames (including any containing a literal backslash or parenthesis, if such accounts exist) still resolve correctly.
