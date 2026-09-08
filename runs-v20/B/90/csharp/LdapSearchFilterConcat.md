## Verdict

Exploitable. CWE-90 (LDAP Injection). Confidence: high.

## Source

`username`, the `[FromQuery]` parameter of `DirectoryLookupController.FindUser` (`LdapSearchFilterConcat.cs:11`) - attacker-controlled via the `api/directory/users` query string, with no validation or escaping applied anywhere between binding and use.

## Sink

`searcher.Filter = "(sAMAccountName=" + username + ")";` (`LdapSearchFilterConcat.cs:17`), a `DirectorySearcher.Filter` assignment built by direct string concatenation. `username` reaches this line unmodified from the controller parameter - a single-hop, unbroken flow.

Sink contract: `DirectorySearcher.Filter` is a plain string property; the setter has no return value and performs no encoding of its own. The subsequent `searcher.FindOne()` executes the filter as-is, returns the first matching `SearchResult` or `null`, and the `null` branch is already handled (`NotFound()`). Nothing about the sink's return, discard, or failure behaviour needs to change to fix this.

Because the value is concatenated raw, an attacker can supply `*` to turn the equality test into a wildcard match, or close the term early with `)(...)` to inject additional filter clauses (e.g. `admin)(|(sAMAccountName=*` type payloads), altering which directory entries the search returns.

## Fix

### File: LdapSearchFilterConcat.cs

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

    // RFC 4515 filter escaping: encodes the metacharacters a filter value must not
    // contain unescaped (*, (, ), backslash, NUL) as their hex escape sequences.
    // Escaping character-by-character in a single pass (rather than sequential
    // string.Replace calls) means an inserted escape sequence is never re-escaped.
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

`username` is escaped for RFC 4515 filter syntax before it is concatenated into `searcher.Filter`. The escape function walks the string once and replaces each of the five filter metacharacters (`\`, `*`, `(`, `)`, NUL) with its two-digit hex escape (`\5c`, `\2a`, `\28`, `\29`, `\00`); every other character, including legitimate values such as an apostrophe or a plus sign, passes through unchanged. Because the replacement happens character-by-character in one pass rather than via sequential `string.Replace` calls, an escape sequence inserted for one character (e.g. the `\` in `\28`) can never be re-matched and escaped again. .NET's `System.DirectoryServices` has no built-in filter-escaping helper, so this hand-rolled encoder implements the RFC 4515 character set the C# guidance specifies. With every metacharacter neutralized, an attacker-supplied `)`, `(`, or `*` can no longer close the existing filter term, open a new clause, or turn the equality test into a wildcard - the value is always interpreted as a literal `sAMAccountName` to match, closing the injection. No allowlist was added: the codebase defines no username format policy for this endpoint, and the guidance is explicit that a security-only pattern would reject legitimate values (e.g. usernames containing characters outside a guessed character class) as a regression rather than a defence.

## Behaviour changes

- Added a private static helper method, `EscapeLdapFilterValue`, and a `using System.Text;` import for `StringBuilder`. Both exist solely to perform the escaping; neither is called from, nor changes the behaviour of, any other code path.
- A username that contains `*`, `(`, `)`, a backslash, or a NUL byte now matches literally instead of being interpreted as filter syntax - this is the intended effect of the fix, not an incidental change: such input already could not name a legitimate `sAMAccountName` (which is a restricted character set in Active Directory), so no valid lookup that previously succeeded is affected.
- All other behaviour is unchanged: `DirectorySearcher.Filter`'s type, the `FindOne()` call, the `NotFound()`/`Ok()` response shapes, and the properties returned are identical to the original.

## Verification

Compiled with the real APIs: copied the fixed file into a scratch ASP.NET Core Web project (`Microsoft.NET.Sdk.Web`, `net8.0-windows`) with a `PackageReference` to `System.DirectoryServices` 8.0.0, alongside a minimal `Program.cs` bootstrapping `WebApplication`/`AddControllers`/`MapControllers`. `dotnet build` succeeded with 0 warnings and 0 errors, confirming `DirectoryEntry`, `DirectorySearcher`, `ControllerBase`, `[ApiController]`/`[Route]`/`[HttpGet]`, and the new `EscapeLdapFilterValue` helper all resolve and type-check correctly against the genuine framework and package APIs.

## Assumptions

None of significance - the language (C#) and sink were unambiguous from the file and finding. No username format policy is documented in the codebase, so no allowlist was added, per the guidance's instruction not to invent one.
