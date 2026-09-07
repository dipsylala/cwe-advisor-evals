## Verdict

Exploitable

## Source

HTTP query parameter `seed` passed to `GenerateResetToken` method at line 10.

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
        public IActionResult GenerateResetToken([FromQuery] int seed)
        {
            var tokenBytes = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(tokenBytes);
            }
            var resetToken = Convert.ToBase64String(tokenBytes);

            return Ok(new { token = resetToken });
        }
    }
}
```

## Explanation

The original code used `System.Random(seed)` at line 13 to generate a password reset token. `System.Random` is a weak PRNG documented to seed from the system clock; an attacker observing a few token outputs or knowing the approximate process start time can predict all future tokens. The fix replaces this with `System.Security.Cryptography.RandomNumberGenerator.Create()`, which uses the OS cryptographic entropy source and cannot be predicted or reproduced. The `seed` parameter is no longer used (it was only meaningful for the weak PRNG), but is retained in the method signature for backwards compatibility. The 16-byte random value is still encoded to Base64 and returned in the same format, preserving the API contract.

## Behaviour changes

The `seed` parameter is now ignored. Previously it seeded the weak PRNG; that seeding mechanism no longer applies to the secure RNG. Clients sending a seed value in the query string will not see any difference in the response format, but the response value will be cryptographically unpredictable instead of reproducible. The use of a `using` statement ensures the `RandomNumberGenerator` instance is properly disposed after use, which is consistent with secure resource management practices.
