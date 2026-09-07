## Verdict

Confirmed: CWE-338 - The code uses `System.Random` to generate cryptographic tokens. This PRNG is not suitable for security-sensitive operations and the seed is derived from an untrusted query parameter, making token generation predictable.

## Source

User-controlled input: The `seed` parameter from the query string on line 10 flows directly into `Random(seed)` on line 13.

## Fix

Replace `System.Random` with `System.Security.Cryptography.RandomNumberGenerator`, which is cryptographically secure and does not accept or need a seed:

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
            using (var rng = RandomNumberGenerator.Create())
            {
                var tokenBytes = new byte[16];
                rng.GetBytes(tokenBytes);
                var resetToken = Convert.ToBase64String(tokenBytes);

                return Ok(new { token = resetToken });
            }
        }
    }
}
```

## Explanation

`System.Random` is a linear congruential generator unsuitable for cryptographic use. Its output is predictable given knowledge of internal state, and seeding it with a user-controlled value makes the token deterministic and reproducible.

`System.Security.Cryptography.RandomNumberGenerator` provides cryptographically secure randomness and is the correct choice for generating security tokens. The seed parameter is not needed and should be removed entirely—cryptographic randomness requires no initialization from external input. The using statement ensures proper disposal of the RNG resource.
