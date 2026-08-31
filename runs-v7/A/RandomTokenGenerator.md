## Verdict

Real. The code uses `System.Random`, a non-cryptographic PRNG, to generate password reset tokens. Combined with a user-controlled seed, the token becomes predictable and an attacker can forge valid reset tokens.

## Source

```csharp
[HttpGet("token")]
public IActionResult GenerateResetToken([FromQuery] int seed)
{
    var rng = new Random(seed);
    
    var tokenBytes = new byte[16];
    rng.NextBytes(tokenBytes);
    var resetToken = Convert.ToBase64String(tokenBytes);
    
    return Ok(new { token = resetToken });
}
```

## Fix

```csharp
using System.Security.Cryptography;

[HttpGet("token")]
public IActionResult GenerateResetToken()
{
    var tokenBytes = new byte[16];
    RandomNumberGenerator.Fill(tokenBytes);
    var resetToken = Convert.ToBase64String(tokenBytes);
    
    return Ok(new { token = resetToken });
}
```

## Explanation

`System.Random` is a non-cryptographic PRNG designed for simulations and games, not security. It produces predictable sequences, especially when seeded with known values. Password reset tokens must be unpredictable to prevent account takeover.

The fix replaces `Random` with `System.Security.Cryptography.RandomNumberGenerator.Fill()`, which uses the operating system's cryptographically secure random source. The user-controlled `seed` parameter is removed entirely—cryptographic operations should never rely on attacker-influenced entropy sources.
