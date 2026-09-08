## Verdict

Confirmed. `GenerateResetToken` seeds `System.Random` with a value taken directly from the request query string and uses it to produce a password-reset token, making the token fully attacker-predictable.

## Source

`[FromQuery] int seed` on `PasswordResetController.GenerateResetToken` (`RandomTokenGenerator.cs:10`) - an HTTP query parameter under direct caller control.

## Fix

### File: RandomTokenGenerator.cs

```csharp
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;

namespace EvalCases.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class PasswordResetController : ControllerBase
    {
        [HttpGet("token")]
        public IActionResult GenerateResetToken()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(16);
            var resetToken = Convert.ToBase64String(tokenBytes);

            return Ok(new { token = resetToken });
        }
    }
}
```

## Explanation

The data flow is source-to-sink in three lines: the `seed` query parameter (line 10) is passed straight into `new Random(seed)` (line 13), and `rng.NextBytes(tokenBytes)` (line 16) then derives the 16-byte reset-token payload from that seeded, deterministic generator. `System.Random`'s algorithm is fully deterministic given its seed, so anyone who calls `GET /api/PasswordReset/token?seed=12345` receives the exact same "random" bytes every time, and the reset token for a given seed is trivially reproducible - this is strictly worse than the usual clock-seeded `Random` finding, because here the caller supplies the seed explicitly rather than having to guess a narrow startup-time window.

The fix replaces the weak, attacker-seedable generator with `RandomNumberGenerator.GetBytes(16)` from `System.Security.Cryptography`, per the loaded C# guidance (`cwe/338/csharp/INDEX.md`), which draws entropy from the OS CSPRNG and takes no caller-supplied seed. The `seed` parameter is removed from the action entirely: its only function was to drive the vulnerable seeding, and a password-reset token endpoint has no legitimate reason to accept randomness input from the client. The sink's contract is otherwise preserved - a 16-byte array is produced and base64-encoded into the same `{ token = ... }` response shape, with no new discarded output, no new failure path (`RandomNumberGenerator.GetBytes` does not throw for a valid positive length), and no other implicit arguments introduced.

Every name introduced by the fix is verified: `RandomNumberGenerator.GetBytes(int)` is named explicitly in `cwe/338/csharp/INDEX.md` as the .NET 6+ replacement API, and `System.Security.Cryptography` is its documented namespace. The fixed file was compiled against a scratch ASP.NET Core Web API project (`dotnet build`, .NET SDK 10.0.203) with the same controller shape and namespace; the build succeeded with zero errors (two pre-existing, unrelated NU1903 advisory warnings from the scaffold's own `Microsoft.OpenApi` package).

## Behaviour changes

- The `seed` query-string parameter is removed from `GET /api/PasswordReset/token`. Any caller currently passing `?seed=...` will have that value silently ignored by ASP.NET Core model binding rather than accepted (removing the parameter is intentional here: it was the sole vector for the vulnerability, and a caller-supplied seed has no legitimate use for a security token).
- Generated tokens are no longer reproducible across calls with the same `seed` value - each call now returns independently unpredictable, OS-CSPRNG-derived bytes, which is the intended remediation outcome rather than a side effect.
