## Verdict

Exploitable. `System.Random` is a seeded deterministic PRNG and is not cryptographically secure. An attacker observing a few password reset token outputs, or knowing the approximate process start time, can predict all future tokens. Password reset tokens are security-sensitive and require cryptographic randomness.

## Source

Query parameter `seed` passed to the controller action, line 10.

## Fix

**Vulnerable code (line 13):**
```csharp
var rng = new Random(seed);
var tokenBytes = new byte[16];
rng.NextBytes(tokenBytes);
var resetToken = Convert.ToBase64String(tokenBytes);
```

**Fixed code:**
```csharp
using System.Security.Cryptography;

// In the method:
var tokenBytes = new byte[16];
RandomNumberGenerator.GetBytes(tokenBytes);
var resetToken = Convert.ToBase64String(tokenBytes);
```

## Explanation

The fix replaces `System.Random` with `System.Security.Cryptography.RandomNumberGenerator.GetBytes()`, which draws entropy directly from the OS cryptographic RNG. This eliminates predictability: the token is no longer seeded from user input or timing, and is cryptographically unpredictable regardless of seed value. The output length (16 bytes = 128 bits) and encoding (Base64) remain unchanged, preserving the token format and downstream contract.

## Behaviour changes

**Removed dependency on seed parameter:** The original code accepted a `seed` query parameter and used it to initialize `System.Random`, making the token reproducible for the same seed. The fixed code ignores the seed parameter entirely, generating fresh entropy on each call. If the seed parameter was intended for testing or debugging, it must be removed from the public API or routed to a separate testing endpoint that does not generate real tokens.
