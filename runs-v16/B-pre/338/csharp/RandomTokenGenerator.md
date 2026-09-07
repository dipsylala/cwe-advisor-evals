## Verdict

Exploitable. `System.Random` is not cryptographically secure and is being used to generate a password-reset token, a security-sensitive value. The PRNG is seeded with user-controlled input (`seed` parameter), making the token reproducible and predictable.

## Source

User-controlled `seed` parameter from the query string at line 10: `[FromQuery] int seed`.

## Fix

**Vulnerable code (line 13-16):**
```csharp
var rng = new Random(seed);
var tokenBytes = new byte[16];
rng.NextBytes(tokenBytes);
```

**Fixed code:**
```csharp
var tokenBytes = RandomNumberGenerator.GetBytes(16);
```

**Namespace addition required:**
Add `using System.Security.Cryptography;` at the top of the file.

## Explanation

The fix replaces `System.Random` with `RandomNumberGenerator.GetBytes()`, which derives entropy from the OS cryptographic entropy source (e.g., `/dev/urandom` on Unix, `CryptGenRandom` on Windows). This eliminates the predictability introduced by the weak PRNG and its user-controlled seed. `RandomNumberGenerator.GetBytes()` requires .NET 6+; for earlier .NET versions, use `RandomNumberGenerator.Create()` followed by `GetBytes(byte[])`. The token is still encoded to Base64 and returned the same way, so the caller interface remains unchanged.

## Behaviour changes

- **API contract change**: The `seed` query parameter is now ignored and unused. This is a breaking API change that should be removed from the method signature unless it serves other purposes in the application. If the parameter is retained for backwards compatibility, document that it no longer controls token generation.
- **Randomness guarantee**: The reset token is now cryptographically unpredictable rather than reproducible from the seed value. Reset tokens cannot be replayed or predicted by supplying the same seed.
