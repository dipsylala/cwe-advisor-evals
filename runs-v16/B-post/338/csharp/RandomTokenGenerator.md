## Verdict

Confirmed. `System.Random` on line 13 is a cryptographically weak PRNG used to generate a password reset token. Even though the seed is user-supplied here, the vulnerability exists independently: `System.Random` produces predictable sequences and should never be used for security-sensitive tokens.

## Source

`[FromQuery] int seed` parameter provides user-controlled input to seed the PRNG. Password reset tokens derived from a predictable generator are exploitable regardless of how the seed is set.

## Fix

**Vulnerable code:**
```csharp
var rng = new Random(seed);

var tokenBytes = new byte[16];
rng.NextBytes(tokenBytes);
var resetToken = Convert.ToBase64String(tokenBytes);
```

**Fixed code (.NET 6+):**
```csharp
using System.Security.Cryptography;

// ... in method:
var tokenBytes = RandomNumberGenerator.GetBytes(16);
var resetToken = Convert.ToBase64String(tokenBytes);
```

**Fixed code (.NET 5 / .NET Framework):**
```csharp
using System.Security.Cryptography;

// ... in method:
var tokenBytes = new byte[16];
RandomNumberGenerator.Create().GetBytes(tokenBytes);
var resetToken = Convert.ToBase64String(tokenBytes);
```

## Explanation

`System.Random` is a seeded, deterministic PRNG—not cryptographically secure. Its outputs are predictable given the seed or a few outputs. Password reset tokens must be cryptographically unpredictable to prevent account takeover.

Replacement with `RandomNumberGenerator.GetBytes()` (.NET 6+) or `RandomNumberGenerator.Create().GetBytes()` (.NET 5/Framework) sources entropy directly from the OS cryptographic entropy pool. The bytes are not reproducible and cannot be predicted without access to the OS entropy source.

The fix removes the weak seed parameter entirely: cryptographic randomness does not depend on a seed—it depends on sufficient entropy from the OS. No seeding is required or permitted.

## Behaviour changes

- Token generation becomes non-deterministic: identical reset requests now produce different tokens (correct behavior for security).
- Token values are now cryptographically unpredictable across application restarts or instances.
- The `seed` query parameter is no longer used. If it was relied upon for testing or replay scenarios, those tests must switch to mocking `RandomNumberGenerator` or capturing generated values from actual invocations.
