## Verdict

Exploitable. Confidence: high.

`GenerateResetToken` seeds `System.Random` with an `int seed` taken directly from the query string (`[FromQuery] int seed`). This is worse than the typical CWE-338 case of a time-seeded PRNG: here the caller supplies the seed outright, so anyone can reconstruct the exact byte sequence `NextBytes` will produce and compute the password-reset token themselves, for any seed value they choose, without observing any prior output.

## Source

- Source: `seed` query-string parameter on `GET api/[controller]/token`, bound via `[FromQuery] int seed` (line 10) - fully attacker-controlled, no validation or transformation before use.
- Sink: `new Random(seed)` (line 13), whose output seeds a 16-byte password-reset token via `rng.NextBytes(tokenBytes)` (line 16), base64-encoded and returned directly to the caller (line 17-19).
- Data flow: request query string -> `seed` parameter -> `Random` constructor -> `NextBytes` -> `resetToken` -> HTTP response body. No intermediate check breaks the path.

## Fix

Library recommendation: none - the fix uses `System.Security.Cryptography.RandomNumberGenerator`, which ships in the .NET base class library. No package or version addition is required. `RandomNumberGenerator.GetBytes(int count)` is available from .NET 6 onward; if this project targets .NET Framework or .NET 5, use `RandomNumberGenerator.Create()` with `GetBytes(byte[])` instead, per the loaded C# guidance.

Vulnerable code:

```csharp
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
```

Fixed code:

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

(`using System.Security.Cryptography;` added to the file's using block alongside the existing `using Microsoft.AspNetCore.Mvc;`.)

## Explanation

The fix replaces the seeded, attacker-controlled `System.Random` with `RandomNumberGenerator.GetBytes(16)`, which draws directly from the OS cryptographic entropy source and cannot be seeded or predicted by a caller. The `seed` query parameter is dropped entirely rather than validated, because it served no legitimate purpose here - a password-reset token must not be derived from any client-supplied input, regardless of range checks - so removing the parameter is part of closing the weakness, not a separate change. The rest of the endpoint's contract is preserved: it still returns a 16-byte token, base64-encoded, in the same `{ token = ... }` response shape.

## Behaviour changes

- The `GenerateResetToken` action no longer accepts a `seed` query parameter; a request that previously included `?seed=...` will now ignore it (ASP.NET Core model binding simply has no parameter to bind to, so the call still succeeds). This is required by the fix: any client-influenced input to token generation is the vulnerability, not an incidental detail of the old implementation.
- Token values are no longer reproducible from a given seed, by design - this is the intended security effect of the fix, not an unintended side effect.
- No change to the response shape, status code, byte length (16 bytes), or encoding (base64) of the token.
