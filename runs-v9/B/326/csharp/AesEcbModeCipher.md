## Verdict

**Exploitable.** Line 21 sets `aes.Mode = CipherMode.ECB` on an `Aes` instance that is then used (lines 24-25) to encrypt attacker-supplied plaintext (`secretNote` from the query string) under a static key. ECB encrypts each 16-byte block independently with no chaining or nonce, so identical plaintext blocks always produce identical ciphertext blocks, both within one response and across repeated calls with the same input. That leaks block-level structure and equality of the protected data directly through the returned ciphertext, and provides no integrity/authentication check, so tampering is undetectable.

## Source

- **Data source**: `secretNote` query-string parameter on `GET api/AesEcbModeCipher/encrypt` (`AesEcbModeCipherController.Encrypt`), converted to `plaintextBytes` on line 16.
- **Weak configuration**: `aes.Mode = CipherMode.ECB` — line 21 (the flagged sink).
- **Sink**: `encryptor.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length)` — line 25, where `encryptor` was created from the ECB-configured `aes` instance.
- Data flow is direct and unconditional: no validation or branch between the mode assignment and the encryption call, so every request through this endpoint is encrypted in ECB mode.

Sink contract established before fixing: `TransformFinalBlock` **returns** the ciphertext bytes, which the caller base64-encodes and returns as the entire HTTP response body via `Ok(...)`. The code **discards** the IV that `Aes.Create()` auto-generates (irrelevant here since ECB does not use an IV). No other arguments are left implicit — `Key`, `Mode`, and `Padding` are all set explicitly. On failure, `TransformFinalBlock` throws `CryptographicException`, which is unhandled and will surface as a 500 response; the fix preserves that behavior.

## Fix

Vulnerable code:

```csharp
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AesEcbModeCipherController : ControllerBase
{
    private static readonly byte[] Key = Encoding.UTF8.GetBytes("0123456789abcdef");

    [HttpGet("encrypt")]
    public IActionResult Encrypt([FromQuery] string secretNote)
    {
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(secretNote);

        using var aes = Aes.Create();
        aes.Key = Key;
        // SAST FINDING: CWE-326 (Inadequate Encryption Strength) reported here. Sink is the next statement.
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;

        using var encryptor = aes.CreateEncryptor();
        byte[] cipherBytes = encryptor.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length);

        return Ok(Convert.ToBase64String(cipherBytes));
    }
}
```

Fixed code:

```csharp
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace EvalCases.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AesEcbModeCipherController : ControllerBase
{
    private static readonly byte[] Key = Encoding.UTF8.GetBytes("0123456789abcdef");

    [HttpGet("encrypt")]
    public IActionResult Encrypt([FromQuery] string secretNote)
    {
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(secretNote);

        byte[] nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        byte[] cipherBytes = new byte[plaintextBytes.Length];
        byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];

        using (var aesGcm = new AesGcm(Key, AesGcm.TagByteSizes.MaxSize))
        {
            aesGcm.Encrypt(nonce, plaintextBytes, cipherBytes, tag);
        }

        byte[] payload = new byte[nonce.Length + cipherBytes.Length + tag.Length];
        Buffer.BlockCopy(nonce, 0, payload, 0, nonce.Length);
        Buffer.BlockCopy(cipherBytes, 0, payload, nonce.Length, cipherBytes.Length);
        Buffer.BlockCopy(tag, 0, payload, nonce.Length + cipherBytes.Length, tag.Length);

        return Ok(Convert.ToBase64String(payload));
    }
}
```

## Explanation

The fix replaces the unauthenticated, block-independent `Aes`/`CipherMode.ECB` path with `AesGcm`, an AEAD cipher, per the knowledge base's CWE-326 C# guidance. A fresh 12-byte nonce is drawn from `RandomNumberGenerator.GetBytes` for every call (`AesGcm.NonceByteSizes.MaxSize` is 12, the one legal value for GCM), so identical plaintexts no longer produce identical ciphertexts and no block-level pattern is exposed. `AesGcm` also computes a 16-byte authentication tag over the ciphertext, so any tampering is detected rather than silently decrypted, which ECB with no MAC could never provide. The existing 16-byte key is reused unchanged — NIST SP 800-57 and the loaded guidance both treat AES-128 as acceptable with no end date, so resizing the key is not required to close this finding, and changing key material would be a separate, unrelated change. The two-parameter `AesGcm(key, tagSizeInBytes)` constructor is used per current .NET guidance; this assumes the project targets .NET 8 or later (see Behaviour changes) — on an earlier target framework, `new AesGcm(Key)` (available since .NET Core 3.0, default 16-byte tag) is the equivalent substitute.

## Behaviour changes

- **Response payload format changed**: the endpoint now returns base64(`nonce (12 bytes) || ciphertext || tag (16 bytes)`) instead of base64(`ciphertext` alone). This is required, not incidental — GCM ciphertext cannot be authenticated or decrypted without the nonce and tag that were used to produce it, and the original code produced no companion endpoint or storage for those values, so they must travel with the ciphertext. Any caller that currently parses the response as raw ECB ciphertext will need to be updated to split out the nonce and tag before decrypting.
- **Ciphertext is now non-deterministic**: encrypting the same `secretNote` twice yields different output each time (because the nonce is random per call), whereas the vulnerable ECB code was deterministic for a given key and plaintext. This is the intended fix — deterministic ciphertext under ECB is exactly what leaked the block-level plaintext patterns.
- **Tampering now causes decryption to fail with an exception** on any correctly-implemented decrypt path, instead of silently producing incorrect plaintext (ECB provides no integrity check). No decrypt method exists in this file, so this changes only what a future/paired decrypt implementation must handle, not observable behavior of this endpoint today.
- **Padding removed**: `PaddingMode.PKCS7` is gone because GCM is a stream-style AEAD mode with no block-padding requirement; ciphertext length now equals plaintext length (plus the separately-appended tag), rather than being rounded up to the next 16-byte boundary as PKCS7-padded ECB output was.
- No change to the key material, the `secretNote` input handling, the HTTP route, or the unhandled-exception behavior on cryptographic failure (`CryptographicException` still propagates as a 500).

**Assumption**: target framework is .NET 8 or later, based on no other version signal being available in the single-file case directory; `AesGcm(key, tagSizeInBytes)` requires .NET 8+. If the project targets an earlier framework, use `new AesGcm(Key)` instead, which is equivalent and available since .NET Core 3.0.
