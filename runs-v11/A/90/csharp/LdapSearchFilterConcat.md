## Verdict

Confirmed LDAP injection vulnerability. Unsanitized user input is concatenated directly into the LDAP filter string, allowing attackers to inject special characters (`*`, `(`, `)`, `\`, `/`) to modify the query logic, bypass authentication, or extract unintended data.

## Source

Line 17 concatenates the `username` parameter directly from user input into the LDAP filter:

```csharp
searcher.Filter = "(sAMAccountName=" + username + ")";
```

An attacker can supply `username = "*"` to match any user, or `username = "admin)(|(uid=*"` to alter the filter logic.

## Fix

Use the `Encoder.LdapFilterEncode()` method from `System.DirectoryServices.Protocols` to escape the username before concatenating:

```csharp
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
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

        string encodedUsername = Encoder.LdapFilterEncode(username);
        searcher.Filter = "(sAMAccountName=" + encodedUsername + ")";

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

The LDAP protocol uses special characters (`*`, `(`, `)`, `\`, `/`) as metacharacters in filter expressions. When user input is concatenated directly into a filter string without encoding, an attacker can inject these characters to alter the filter's meaning.

`Encoder.LdapFilterEncode()` escapes each of these special characters by prefixing them with a backslash and their hex representation (e.g., `*` becomes `\2a`), ensuring the input is treated as literal filter data rather than filter syntax. This prevents the injection from modifying the query structure while allowing legitimate searches to proceed normally.

The fix adds the required `using System.DirectoryServices.Protocols;` namespace and encodes the username parameter immediately before use in the filter string.
