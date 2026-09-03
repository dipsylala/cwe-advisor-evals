## Verdict

Exploitable. ECB mode leaks plaintext patterns through identical ciphertext blocks, enabling an attacker to observe plaintext structure from encrypted output.

## Source

`Aes.Create()` produces an uninitialized cipher object (line 18); the mode is then explicitly set to `CipherMode.ECB` (line 21).

## Fix

**Vulnerable code:**
```csharp
using var aes = Aes.Create();
aes.Key = Key;
// SAST FINDING: CWE-326 (Inadequate Encryption Strength) reported here. Sink is the next statement.
aes.Mode = CipherMode.ECB;
aes.Padding = PaddingMode.PKCS7;

using var encryptor = aes.CreateEncryptor();
byte[] cipherBytes = encryptor.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length);

return Ok(Convert.ToBase64String(cipherBytes));
```

**Fixed code:**
```csharp
byte[] nonce = RandomNumberGenerator.GetBytes(12);
byte[] tag = new byte[16];

using var aesGcm = new AesGcm(Key);
byte[] cipherBytes = new byte[plaintextBytes.Length];
aesGcm.Encrypt(nonce, plaintextBytes, cipherBytes, tag);

// Persist nonce, ciphertext, and tag together
byte[] payload = new byte[nonce.Length + cipherBytes.Length + tag.Length];
Array.Copy(nonce, 0, payload, 0, nonce.Length);
Array.Copy(cipherBytes, 0, payload, nonce.Length, cipherBytes.Length);
Array.Copy(tag, 0, payload, nonce.Length + cipherBytes.Length, tag.Length);

return Ok(Convert.ToBase64String(payload));
```

## Explanation

ECB mode applies the same transformation to each plaintext block independently, causing identical plaintext blocks to produce identical ciphertext blocks. This exposes plaintext patterns and enables frequency analysis. `AesGcm` provides authenticated encryption: each message is encrypted with a unique nonce and produces authentication metadata (tag) that detects tampering before decryption. The nonce must be randomly generated per message and never reused under the same key; the fix generates a fresh 12-byte nonce using `RandomNumberGenerator.GetBytes(12)` and persists it alongside the ciphertext and tag so the recipient can decrypt. The tag is generated during encryption and verified during decryption, closing the integrity gap that ECB leaves open.

## Behaviour changes

- **Nonce generation and transmission**: The original code produced only ciphertext; the fixed code generates a random nonce per encryption and includes it in the output. The caller must transmit and store the nonce alongside the ciphertext so decryption can retrieve and use it.
- **Output format**: The original code returned `Base64(ciphertext)`; the fixed code returns `Base64(nonce || ciphertext || tag)`. Decryption must split the payload into these three components before calling `AesGcm.Decrypt()`.
- **Decryption logic required**: No decryption endpoint is shown in the finding, so a corresponding decryption method must be added to reverse the encryption: extract nonce, ciphertext, and tag from the incoming payload, and call `aesGcm.Decrypt(nonce, ciphertext, tag, plaintextBytes)`. If decryption is not implemented, the encrypted data becomes irretrievable.
- **API replacement**: Switched from `Aes.CreateEncryptor()` (unauthenticated symmetric cipher) to `AesGcm.Encrypt()` (authenticated encryption). The interface is different: `Aes` uses a stream-based encryptor; `AesGcm` takes all inputs at once and returns the ciphertext in-place.
