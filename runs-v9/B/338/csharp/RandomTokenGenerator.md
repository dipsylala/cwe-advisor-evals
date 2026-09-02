## Verdict

exploitable (confidence: high)

## Source

`seed`, an `[FromQuery] int` parameter on `GenerateResetToken` (line 10) — fully attacker-controlled, taken directly from the request query string with no validation.

## Fix

Vulnerable code (`RandomTokenGenerator.cs`):

```csharp
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class PasswordResetController : ControllerBase
    {
        [HttpGet("token")]
        public IActionResult GenerateResetToken([FromQuery] int seed)
        {
            // SAST FINDING: CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)) reported here. Sink is the next statement.
            var rng = new Random(seed);

            var tokenBytes = new byte[16];
            rng.NextBytes(tokenBytes);
            var resetToken = Convert.ToBase64String(tokenBytes);

            return Ok(new { token = resetToken });
        }
    }
}
```

Fixed code:

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

`GenerateResetToken` produced a password-reset token from `System.Random` seeded directly with the caller-supplied `seed` query parameter, then encoded the generator's output as the token. `System.Random` is a deterministic, non-cryptographic PRNG, and seeding it explicitly with attacker-controlled input means anyone who calls the endpoint can reproduce the exact 16-byte token deterministically — this is worse than the general "time-seeded `Random`" case the CWE-338 guidance describes, since no clock-guessing is even required. The fix replaces the sink with `RandomNumberGenerator.GetBytes(16)` (.NET 6+), which draws directly from the OS cryptographic entropy source and takes no seed, so the output is unpredictable and cannot be reproduced by a caller. The `seed` parameter is removed because a CSPRNG has no seed input to accept, and retaining it as a dead, unused parameter would leave a misleading vestige of the attacker-control path in the API surface.

## Behaviour changes

- Removed the `seed` query parameter from the endpoint signature. It served only to seed the vulnerable `Random` instance; `RandomNumberGenerator` takes no seed, so the parameter has no remaining purpose. This is a public API surface change: any caller currently passing `?seed=...` will still succeed (ASP.NET Core ignores unrecognized query parameters by default) but the value will be silently ignored rather than controlling the output as before — which is the intended effect of the fix, not an incidental one.
- Removed the intermediate `var rng = new Random(seed)` and `rng.NextBytes(tokenBytes)` steps in favor of a single `RandomNumberGenerator.GetBytes(16)` call that returns the byte array directly, rather than filling a pre-allocated one. Output shape (`byte[16]` → Base64) and the JSON response contract (`{ token = resetToken }`) are unchanged.
- No other differences: return type, route, HTTP verb, and error behaviour (both the original and `RandomNumberGenerator.GetBytes` do not throw under normal operation) are preserved.
