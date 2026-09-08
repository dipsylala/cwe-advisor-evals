## Verdict

Confirmed. `username` from `[FromQuery]` flows unescaped into the LDAP search filter string built at line 17, then into `DirectorySearcher.FindOne()`. A value containing filter metacharacters (`*`, `(`, `)`, `\`, NUL) changes the filter's structure, letting a caller broaden the match (e.g. `*` to enumerate accounts) or inject additional filter clauses.

## Source

`username` — the `[FromQuery] string username` parameter of `DirectoryLookupController.FindUser`, `LdapSearchFilterConcat.cs` line 11. It reaches the sink unmodified via string concatenation at line 17 (`searcher.Filter = "(sAMAccountName=" + username + ")"`), which is then executed by `searcher.FindOne()` at line 19.

## Fix

### File: LdapSearchFilterConcat.cs

```csharp
using System.DirectoryServices;
using System.Globalization;
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

    // Escapes the characters RFC 4515 reserves in an LDAP search filter
    // assertion value, so user input cannot alter the filter's structure.
    private static string EscapeLdapFilterValue(string value)
    {
        var builder = new StringBuilder(value.Length);

        foreach (var c in value)
        {
            switch (c)
            {
                case '\\':
                    builder.Append("\\5c");
                    break;
                case '*':
                    builder.Append("\\2a");
                    break;
                case '(':
                    builder.Append("\\28");
                    break;
                case ')':
                    builder.Append("\\29");
                    break;
                case '\0':
                    builder.Append("\\00");
                    break;
                default:
                    if (c > 0x7f)
                    {
                        foreach (var b in Encoding.UTF8.GetBytes(c.ToString()))
                        {
                            builder.Append('\\').Append(b.ToString("x2", CultureInfo.InvariantCulture));
                        }
                    }
                    else
                    {
                        builder.Append(c);
                    }
                    break;
            }
        }

        return builder.ToString();
    }
}
```

## Explanation

`System.DirectoryServices` has no built-in filter-escaping helper (unlike, say, a parameterized SQL API), so the fix adds one and applies it to every value interpolated into `DirectorySearcher.Filter`. `EscapeLdapFilterValue` implements the RFC 4515 assertion-value escaping: each occurrence of `\`, `*`, `(`, `)`, and NUL is replaced with its `\XX` hex-escaped form, and non-ASCII characters are escaped byte-by-byte after UTF-8 encoding so multi-byte characters cannot be split into bytes that themselves collide with a reserved character. Escaping rather than stripping or allowlisting is deliberate: a denylist or character-strip would either miss encodings or turn a rejected value into a different, unintended valid one, and a strict character allowlist would reject legitimate usernames (e.g. accented characters, apostrophes) that this endpoint's domain does not itself constrain — escaping preserves the caller's literal value while making it impossible for that value to change the filter's grammar.

The value is escaped only at the point it is concatenated into the filter string (line where `searcher.Filter` is assigned), not earlier, so the original `username` is still available for logging or further validation without carrying escape sequences into unrelated code paths. The rest of the flow (`DirectorySearcher.FindOne()`, the properties read from the result) is unchanged, since the vulnerability is entirely in how the filter string is constructed, not in how the result is consumed.

Verification: constructing a filter with `username = "*"` before the fix yields `(sAMAccountName=*)`, matching every account; after the fix it yields `(sAMAccountName=\2a)`, an assertion value of the literal single character `*`, matching only an account named `*`. Likewise `username = "a)(uid=*"` before the fix yields `(sAMAccountName=a)(uid=*)`, injecting a second clause; after the fix the parentheses are escaped to `\28`/`\29`, so the whole value is treated as one literal assertion value with no injected clause.
