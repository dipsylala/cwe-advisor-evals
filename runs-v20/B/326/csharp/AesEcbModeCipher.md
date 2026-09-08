## Verdict

exploitable

- cwe_id: CWE-326
- location: `AesEcbModeCipher.cs`, line 21 (`aes.Mode = CipherMode.ECB;`), sink executed at line 25 (`encryptor.TransformFinalBlock`)
- confidence: high

## Source

`secretNote`, the `[FromQuery]` string parameter of `Encrypt`, is attacker-controlled request input. It flows unmodified through `Encoding.UTF8.GetBytes(secretNote)` into `plaintextBytes`, which is passed directly to `encryptor.TransformFinalBlock` - the same `aes` instance whose `Mode` was set to `CipherMode.ECB` two lines above. There is no validation or transformation between source and sink, so the trace is direct and the finding is exploitable: ECB encrypts each 16-byte block independently with no chaining or IV, so identical plaintext blocks (e.g. repeated substrings in `secretNote`, or repeated calls with related inputs sharing structure) always produce identical ciphertext blocks, letting an observer infer patterns in the protected data without recovering the key.

Sink contract before the fix:
- Returns: `Ok(Convert.ToBase64String(cipherBytes))` - a 200 response body containing only the raw ciphertext, base64-encoded.
- Discards: nothing extra is computed; `aes.IV` is left at its auto-generated default but is never read or used, since ECB ignores IV entirely.
- Arguments left implicit: `aes.IV` (auto-generated, unused under ECB); no MAC/tag is computed anywhere.
- Failure behaviour: `TransformFinalBlock` throws `CryptographicException` on cryptographic failure (not reachable here since padding is well-formed for arbitrary UTF-8 input); an unhandled exception propagates to ASP.NET Core's default error handling (500 response). A null `secretNote` throws `ArgumentNullException` from `Encoding.UTF8.GetBytes`, pre-existing behaviour unrelated to this finding.

## Fix

### File: AesEcbModeCipher.cs

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
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;

    [HttpGet("encrypt")]
    public IActionResult Encrypt([FromQuery] string secretNote)
    {
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(secretNote);

        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        byte[] cipherBytes = new byte[plaintextBytes.Length];
        byte[] tag = new byte[TagSizeBytes];

        using var aesGcm = new AesGcm(Key, TagSizeBytes);
        aesGcm.Encrypt(nonce, plaintextBytes, cipherBytes, tag);

        byte[] payload = new byte[nonce.Length + tag.Length + cipherBytes.Length];
        Array.Copy(nonce, 0, payload, 0, nonce.Length);
        Array.Copy(tag, 0, payload, nonce.Length, tag.Length);
        Array.Copy(cipherBytes, 0, payload, nonce.Length + tag.Length, cipherBytes.Length);

        return Ok(Convert.ToBase64String(payload));
    }
}
```

## Explanation

The fix replaces unauthenticated `Aes`/`CipherMode.ECB` with `AesGcm`, an authenticated encryption mode, per the loaded CWE-326 C# guidance's remediation step to replace ECB with an AEAD mode. Each call generates a fresh 12-byte nonce with `RandomNumberGenerator.GetBytes` (the only legal nonce length for `AesGcm`, per the guidance), uses the .NET 8+ `AesGcm(key, tagSizeInBytes)` constructor with an explicit 16-byte tag (the maximum of `AesGcm.TagByteSizes`, `12..16`), and calls `Encrypt(nonce, plaintext, ciphertext, tag)`. Because GCM turns each plaintext block into a keystream XOR rather than an independent block cipher, identical plaintext blocks no longer produce identical ciphertext blocks, and the tag lets a future decryption path detect any tampering instead of decrypting a modified ciphertext silently - closing both the pattern-leakage and the missing-integrity aspects of the original ECB finding. The 16-byte symmetric key is unchanged: `AesGcm` accepts 16/24/32-byte keys (AES-128/192/256-GCM), and per the general CWE-326 guidance AES-128 is not itself a finding, so widening the key was not required to close this weakness and was left alone to keep the change scoped to the mode.

## Behaviour changes

- Response payload format: the original returned only the base64 ciphertext; the fix returns base64(`nonce (12 bytes) || tag (16 bytes) || ciphertext`). This is required because, unlike ECB, GCM decryption needs the nonce and authentication tag that were used to produce the ciphertext - there is no way to make the ciphertext independently decryptable without carrying them. This endpoint only encrypts (no corresponding decrypt endpoint exists in this file to keep binary-compatible with), so there is no existing consumer whose parsing this breaks within the given code; any external caller that expects a bare ciphertext blob will need to be updated to split the new payload into its three fields before decrypting.
- Response length: for a plaintext of length N, the response body is now 28 bytes longer (12-byte nonce + 16-byte tag) before base64 encoding, versus the original's ciphertext-only, PKCS7-padded length. This is a direct consequence of carrying the nonce and tag and not a separate change.
- Everything else is unchanged: same key material, same HTTP route/verb/parameter, same 200-on-success / unhandled-exception-on-failure behaviour, same `Ok(Convert.ToBase64String(...))` response shape.

Verification: compiled the fixed file in a scratch ASP.NET Core project (`net10.0`, `Microsoft.NET.Sdk.Web`, matching the framework's `ApiController`/`ControllerBase`/`FromQuery` usage) with `dotnet build` - build succeeded, 0 warnings, 0 errors. Every API introduced by the fix (`AesGcm`, `AesGcm(byte[], int)` constructor, `AesGcm.Encrypt`, `RandomNumberGenerator.GetBytes(int)`, `Array.Copy`) is named either in the loaded `cwe/326/csharp/INDEX.md` guidance or is `System`/`System.Security.Cryptography` standard library.

Assumption: the project's target framework was not visible in the case directory (only the single source file was provided), so the fix uses the .NET 8+ `AesGcm(key, tagSizeInBytes)` constructor the guidance recommends; if the real project targets an earlier framework, the tag-less `AesGcm(key)` constructor (obsolete under `SYSLIB0053` from .NET 8) would be needed instead.
