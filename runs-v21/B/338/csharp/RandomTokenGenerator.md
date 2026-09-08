## Verdict

Exploitable. The code uses `System.Random` seeded with a user-supplied value to generate password reset tokens. An attacker who knows or can infer the seed can predict all subsequent "random" values and forge reset tokens.

## Source

The user-supplied `seed` parameter at line 10, passed via HTTP query string (`[FromQuery] int seed`).

## Sink

Line 13: `var rng = new Random(seed);` — creates a cryptographically weak PRNG in a security-sensitive context (password reset token generation).

## Fix

### File: RandomTokenGenerator.cs

```csharp
using System.Security.Cryptography;
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
            var tokenBytes = new byte[16];
            RandomNumberGenerator.Create().GetBytes(tokenBytes);
            var resetToken = Convert.ToBase64String(tokenBytes);

            return Ok(new { token = resetToken });
        }
    }
}
```

## Explanation

The fix replaces `System.Random` (a general-purpose, cryptographically weak PRNG) with `System.Security.Cryptography.RandomNumberGenerator`, which draws entropy from the operating system's cryptographic RNG. `RandomNumberGenerator.Create()` instantiates a platform-appropriate secure RNG, and `GetBytes()` fills the byte array with cryptographically secure random values. This ensures that password reset tokens are unpredictable and non-reproducible, eliminating the weakness. The token is then Base64-encoded and returned as before, preserving the original response format.

## Behaviour changes

- **Seed parameter ignored**: The `seed` query parameter is no longer used. This is intentional and correct — cryptographic randomness must never be seeded with user input or predictable values. Removing this dependency closes the vulnerability and improves the security posture.
- **Random source changed**: Replaced `System.Random` (deterministic, seeded PRNG) with `System.Security.Cryptography.RandomNumberGenerator` (OS-backed cryptographic entropy).
- **Import added**: Added `using System.Security.Cryptography;` to access the secure RNG API.
- **No instance variable**: Removed the `rng` variable; bytes are generated directly via a factory method call.

All other behavior is preserved: the token is still 16 bytes, still Base64-encoded, and still returned with the same HTTP response structure.
