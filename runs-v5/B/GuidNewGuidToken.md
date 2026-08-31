## Verdict

exploitable (confidence: high)

CWE-330 - Use of Insufficiently Random Values. `Guid.NewGuid()` is CSPRNG-backed on modern .NET, so this is not a "predictable source" defect; it is a genuine finding because the value is used as a password-reset token: a v4 GUID carries only 122 bits of entropy (6 bits are fixed version/variant bits) and its structured bit layout makes it unfit as a pseudorandom function output, falling short of the >=128-bit non-guessable-token floor (OWASP ASVS) that a bearer credential like a reset token needs.

## Source

`EvalCases.Controllers.PasswordResetController.RequestReset`, `GuidNewGuidToken.cs:22`:

```
string resetToken = Guid.NewGuid().ToString();
```

The value is generated directly (no attacker-controlled input feeds it) and flows straight to the sink: it is used as the key in the static `ResetTokens` dictionary (line 24) and returned verbatim to the caller as the password-reset token (line 26). Sink contract: the call returns a 36-character hyphenated hex string, the caller stores it and echoes it back in the JSON response, and neither `Guid.NewGuid()` nor `.ToString()` throw under normal operation - the fix must preserve a token that is safe to use as a dictionary key and to serialize as a JSON string value.

## Fix

Vulnerable code:

```csharp
// SAST FINDING: CWE-330 (Use of Insufficiently Random Values) reported here. Sink is the next statement.
string resetToken = Guid.NewGuid().ToString();
```

Fixed code:

```csharp
using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;
// ...
string resetToken = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
```

(add `using System.Security.Cryptography;` and `using Microsoft.AspNetCore.WebUtilities;` to the file's usings; `System.Collections.Concurrent`, `Microsoft.AspNetCore.Mvc`, and the rest of the class are unchanged)

## Explanation

`RandomNumberGenerator.GetBytes(int)` (static, .NET 6+) draws directly from the OS CSPRNG and returns 32 bytes (256 bits) of uniform entropy, well clear of the 128-bit floor, with no fixed/structured bits the way a GUID's version and variant nibbles are fixed. `WebEncoders.Base64UrlEncode` (available in ASP.NET Core since 1.0, so no new package is needed given the project already references `Microsoft.AspNetCore.Mvc`) turns the raw bytes into a URL-safe, unpadded string suitable for a query parameter or JSON field, rather than hand-rolling the `+`/`/` to `-`/`_` substitution. This replaces the source with a byte-oriented CSPRNG output sized to the ASVS floor, closing the entropy gap; it does not touch how the token is stored or returned.

## Behaviour changes

- Token format changes from a 36-character hyphenated hex GUID string (e.g. `3fa85f64-5717-4562-b3fc-2c963f66afa6`) to a 43-character unpadded Base64URL string over 32 random bytes. Reason: closes the entropy/structure gap identified above; both are opaque strings used only as a dictionary key and a JSON field value, so no consumer parses the old GUID shape.
- Token entropy increases from 122 bits (with 6 fixed bits) to 256 bits of uniform randomness. Reason: this is the fix itself, not a side effect.
- None of the surrounding logic changes: the token is still stored as the `ResetTokens` dictionary key against the submitted email and returned in the same `{ token = resetToken }` JSON shape. No previously issued tokens exist to rotate - `ResetTokens` is an in-memory, process-lifetime `ConcurrentDictionary`, so any token issued by the old generator is already gone on process restart and none survive the code change.
