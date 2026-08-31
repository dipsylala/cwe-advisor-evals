## Verdict

CWE-326 (Inadequate Encryption Strength) - **exploitable**. Confidence: high.

`AesEcbModeCipherController.Encrypt` (`AesEcbModeCipher.cs:21`) sets `aes.Mode = CipherMode.ECB` before encrypting. ECB is deterministic and unauthenticated: identical plaintext blocks always produce identical ciphertext blocks, so repeated or structured input leaks patterns regardless of what value is supplied, and nothing detects tampering. This holds for every call to the endpoint, not just specific inputs.

Assumption: target framework is .NET 8 or later, so the tag-size `AesGcm` constructor is available without the `SYSLIB0053` obsoletion warning that applies to the tag-less constructor from .NET 8 onward. No project file was in scope to confirm this; if the target is older than .NET 8, the tag-less `AesGcm(key)` constructor is used instead with an explicit tag buffer, which works identically on earlier frameworks.

## Source

- **Source**: `secretNote`, the query-string parameter on `GET api/AesEcbModeCipher/encrypt` (`[FromQuery] string secretNote`), UTF-8 encoded into `plaintextBytes`. This is the data being protected, not attacker-controlled configuration.
- **Sink**: `aes.Mode = CipherMode.ECB` (line 21), which puts the `Aes` instance created via `Aes.Create()` into ECB mode, followed by `encryptor.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length)` (line 25), which performs the actual ECB encryption using that mode.
- Sink contract before the fix: `TransformFinalBlock` returns the padded ciphertext for the whole input; the controller base64-encodes it and returns it as the entire response body. No IV, nonce, or authentication tag is produced or persisted, and failure behavior is a `CryptographicException` on malformed input (e.g. `secretNote` that fails UTF-8 handling upstream) - the fix must keep the same return shape (a single base64 string as the `200 OK` body).

## Fix

Vulnerable code (`AesEcbModeCipher.cs`):

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
        byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];
        byte[] cipherBytes = new byte[plaintextBytes.Length];

        using (var aesGcm = new AesGcm(Key, AesGcm.TagByteSizes.MaxSize))
        {
            aesGcm.Encrypt(nonce, plaintextBytes, cipherBytes, tag);
        }

        byte[] payload = new byte[nonce.Length + tag.Length + cipherBytes.Length];
        Buffer.BlockCopy(nonce, 0, payload, 0, nonce.Length);
        Buffer.BlockCopy(tag, 0, payload, nonce.Length, tag.Length);
        Buffer.BlockCopy(cipherBytes, 0, payload, nonce.Length + tag.Length, cipherBytes.Length);

        return Ok(Convert.ToBase64String(payload));
    }
}
```

## Explanation

The fix replaces the unauthenticated, deterministic `Aes`/`CipherMode.ECB` pipeline with `AesGcm`, an AEAD cipher, as prescribed by the C# guidance for this CWE. A fresh 12-byte nonce is drawn from `RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize)` for every call - `NonceByteSizes` accepts only 12 bytes for GCM, so this is the one legal value, not an arbitrary maximum - which removes the pattern-preserving determinism that made ECB unsafe: the same `secretNote` now produces different ciphertext on every call. The 16-byte authentication tag produced by `AesGcm.Encrypt` lets a future decrypt path detect any tampering with the ciphertext, closing the "no integrity check" half of the weakness that ECB and unauthenticated CBC share. The existing 16-byte `Key` is left untouched: NIST SP 800-57 rates AES-128 as acceptable with no end date, so the key size itself was never the finding, only the mode. `PaddingMode.PKCS7` is dropped because GCM is a stream-cipher construction with no block-padding requirement.

## Behaviour changes

- **Response payload format changed**: the endpoint previously returned `Convert.ToBase64String(cipherBytes)` (raw ciphertext only); it now returns `Convert.ToBase64String(nonce || tag || cipherBytes)`. This is required by the fix - GCM decryption is impossible without the nonce, and integrity verification is impossible without the tag, so both must travel with the ciphertext. Any caller that decodes the base64 and expects only ciphertext bytes will break and needs the corresponding decrypt path updated to slice off the leading 12-byte nonce and 16-byte tag first.
- **Ciphertext length changed**: GCM output is exactly `plaintextBytes.Length` bytes (no padding), versus the previous PKCS7-padded length rounded up to the AES block size. This follows directly from replacing a block-padded mode with a stream-style AEAD mode and is not separately correctable.
- **No dual-read path added**: this file only exposes an `encrypt` endpoint, with no corresponding decrypt endpoint or persisted ciphertext store in scope, so there is no existing ECB-encrypted data in this code path that a dual-read migration would need to cover. If ciphertext produced by the original ECB endpoint is stored anywhere outside this file, that data cannot be decrypted by the new `AesGcm` path and needs a separate migration, which is outside this fix's scope.
- All other behavior (route, HTTP verb, parameter name, 200/base64-string response shape, static key material) is unchanged.
