## Verdict
Confirmed. `FindUser` builds an LDAP search filter by directly concatenating the caller-supplied `username` query parameter into `searcher.Filter` with no escaping. A value such as `*)(uid=*` or `*)(|(objectClass=*` lets an attacker widen or rewrite the filter's boolean logic to bypass the intended match (e.g. enumerate all directory entries or force a match on an arbitrary account) or use `)(&` / null-byte tricks to terminate and inject additional clauses, since none of `( ) * \ NUL` are neutralized before being placed inside the filter string.

## Source
`username` — the `[FromQuery] string username` parameter of `FindUser(string username)`, read directly off the incoming HTTP request query string (`GET /api/directory/users?username=...`) with no validation or encoding applied before use.

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
        if (string.IsNullOrWhiteSpace(username))
        {
            return BadRequest();
        }

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

    // Escapes an LDAP search filter value per RFC 4515 so it cannot break out
    // of the surrounding filter clause.
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
`System.DirectoryServices` has no built-in filter-encoding helper, so the value must be escaped by hand before it is concatenated into `searcher.Filter`. RFC 4515 defines the LDAP search filter escaping rules: the five characters that carry syntactic meaning inside a filter — `\`, `*`, `(`, `)`, and NUL — must be replaced with their `\XX` hex-escaped form (backslash followed by the two-digit hex code of the byte), and any other character is passed through unchanged. Escaping `\` first is required so a later escape sequence added for another character is not itself re-escaped. `/` is also escaped here as defense-in-depth against DN-based lookups elsewhere in the same LDAP path, though it carries no special meaning inside a filter clause itself.

This closes the injection because none of the characters an attacker needs to break out of the `(sAMAccountName=...)` clause — `)` to close it early, `(` and `*` to add new clauses or wildcard-match, `\` to smuggle further escapes — can reach the filter unescaped; they are rendered as literal hex-escaped bytes that `DirectorySearcher` matches against literally rather than interpreting as filter syntax. The added `IsNullOrWhiteSpace` check is a minor input-validation improvement and not itself the fix — the escaping is what neutralizes the injection.

A denylist-based fix (stripping or rejecting individual characters) is weaker here: it can miss encoding variants or leave the value in an unexpected state, whereas hex-escaping is the mechanism the LDAP filter grammar itself defines for embedding literal values, so it handles every character in the reserved set correctly regardless of position or combination.
