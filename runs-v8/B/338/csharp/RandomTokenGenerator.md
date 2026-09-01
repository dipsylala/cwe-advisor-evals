## Verdict

CONFIRMED. Line 13 uses `System.Random(seed)` with a user-supplied seed for generating a password-reset token. This is cryptographically weak and predictable. System.Random is a deterministic PRNG documented as seeding from the system clock; an attacker who observes the process start time or a few outputs can predict all generated values. Seeding it explicitly with user input amplifies the weakness.

## Source

File: RandomTokenGenerator.cs, line 13  
Vulnerable sink: `new Random(seed)` where `seed` is derived from user input via `[FromQuery] int seed`

Data flow:
- Line 10: `seed` parameter originates from HTTP query string (untrusted user input)
- Line 13: `new Random(seed)` - Instantiates a cryptographically weak PRNG with the user-controlled seed
- Line 16: `rng.NextBytes(tokenBytes)` - Generates token bytes using the seeded, predictable PRNG
- Line 17-19: Token is base64-encoded and returned to client

This is security-sensitive context: the token is used to verify the user's identity in a password-reset flow. An attacker who can predict the token can reset any user's password.

## Fix

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
            var tokenBytes = new byte[16];
            RandomNumberGenerator.GetBytes(tokenBytes);
            var resetToken = Convert.ToBase64String(tokenBytes);

            return Ok(new { token = resetToken });
        }
    }
}
```

Changes:
- Removed `[FromQuery] int seed` parameter - cryptographically secure PRNGs must not be seeded from user input, or any predictable source
- Added `using System.Security.Cryptography;` 
- Replaced `new Random(seed); rng.NextBytes(tokenBytes);` with direct call to `RandomNumberGenerator.GetBytes(tokenBytes)` on line 14
- `RandomNumberGenerator.GetBytes()` uses the OS cryptographic entropy source; it cannot be seeded and is suitable for security-sensitive token generation

## Explanation

`System.Random` is a seeded deterministic PRNG unsuitable for cryptography. The fix replaces it with `RandomNumberGenerator.GetBytes()`, which uses the OS cryptographic entropy source (e.g., `/dev/urandom` on Unix, `CryptGenRandom` on Windows). This is documented in Microsoft's CWE-338 guidance as the correct replacement for `System.Random` in security contexts.

The seed parameter is removed because cryptographically secure generators must not be seeded from user input or any low-entropy source—doing so reintroduces predictability. The OS entropy source is already properly seeded by the kernel and cannot be influenced by callers.

The token is still base64-encoded and returned identically to the original code; only the entropy source changes.

## Behaviour changes

- The `seed` query parameter is no longer accepted; requests including it will be ignored (or return an error if the framework enforces strict parameter matching)
- Tokens are now generated using the OS cryptographic entropy source instead of a user-seeded deterministic algorithm
- Token values are now unpredictable and cannot be reproduced by an attacker, even if they observe the process start time or a few token samples
- Token generation is now cryptographically secure and suitable for password-reset verification
