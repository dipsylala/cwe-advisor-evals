## Verdict

Real vulnerability. `System.Random` with attacker-controlled seed produces cryptographically predictable tokens used for password reset, a security-critical function.

## Source

File: RandomTokenGenerator.cs  
Line: 13  
Function: `GenerateResetToken`  
Vulnerable Pattern: `var rng = new Random(seed);` where `seed` is untrusted query parameter input  
Usage: `rng.NextBytes(tokenBytes)` generates password reset token bytes

## Fix

Replace `System.Random` with cryptographically secure `RandomNumberGenerator`. Remove the `seed` parameter entirely since password reset tokens must be non-deterministic:

```csharp
using System.Security.Cryptography;

[HttpGet("token")]
public IActionResult GenerateResetToken()
{
    var tokenBytes = RandomNumberGenerator.GetBytes(16);
    var resetToken = Convert.ToBase64String(tokenBytes);

    return Ok(new { token = resetToken });
}
```

## Explanation

`System.Random` is a seeded deterministic PRNG unsuitable for security tokens. An attacker providing a known seed value (or guessing seed from timing/process info) can reproduce the exact token sequence. `RandomNumberGenerator.GetBytes()` uses the OS cryptographic entropy source, ensuring tokens are unpredictable and non-reproducible. The `seed` parameter is removed because password reset tokens must never be deterministic or controllable by any user input—each token must be generated fresh from secure entropy. This satisfies the method's contract (returns a token-bearing response) while eliminating the predictability vulnerability.

## Behaviour changes

- Password reset tokens are now cryptographically unpredictable
- Tokens cannot be reproduced by the same request (removing the `seed` parameter dependency)
- Each token call generates a fresh 16-byte value from OS entropy
- API endpoint signature changes: `/api/passwordreset/token` no longer accepts `seed` query parameter
- Test-reproducibility: Tests that relied on seeded randomness must use mocks or be rewritten with fixed token expectations rather than seeded generation
