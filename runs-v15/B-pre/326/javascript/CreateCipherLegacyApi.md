## Verdict

CONFIRMED. The call to `crypto.createCipher('aes-256-cbc', passphrase)` at line 16 is a weak-key-derivation and unauthenticated-encryption issue. `crypto.createCipher()` derives the encryption key from the passphrase using MD5 (deprecated, removed in Node 22+), and CBC mode lacks authentication, exposing the ciphertext to padding-oracle attacks. The passphrase is attacker-controlled via `req.body.passphrase`, so the weakness is reachable.

## Source

**File**: `evals/cases/326/javascript/CreateCipherLegacyApi/CreateCipherLegacyApi.js`

**Data Flow**:
- Source: `req.body.passphrase` (untrusted user input)
- Sink: `crypto.createCipher('aes-256-cbc', passphrase)` (line 16)
- The cipher encrypts user-controlled plaintext with `.update()` and `.final()`, returning the encrypted result to the client

**Why it's weak**:
- `crypto.createCipher()` is deprecated and removed in Node 22+; it uses MD5 to derive the key from the passphrase, which is cryptographically weak
- CBC mode without authentication is vulnerable to padding-oracle decryption attacks (NIST restricts 3DES for encryption; AES-256-CBC is permissible but only with authenticated encryption in modern deployments)
- No explicit, fresh IV is generated; it is derived from the password alongside the key

## Fix

Replace the weak cipher setup with authenticated encryption using AES-256-GCM and a proper password-based key derivation:

```javascript
const express = require('express');
const crypto = require('crypto');

const router = express.Router();

// Encrypts a note's body using a passphrase supplied by the client.
router.post('/notes/encrypt', (req, res) => {
  const passphrase = req.body.passphrase;
  const plaintext = req.body.body;

  if (!passphrase || !plaintext) {
    return res.status(400).json({ error: 'passphrase and body are required' });
  }

  // Generate a random salt and IV for this message
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);

  // Derive a strong key from the passphrase using PBKDF2-SHA256
  crypto.pbkdf2(passphrase, salt, 600000, 32, 'sha256', (err, key) => {
    if (err) {
      return res.status(500).json({ error: 'Key derivation failed' });
    }

    try {
      // Use AES-256-GCM for authenticated encryption
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

      let encrypted = cipher.update(plaintext, 'utf8', 'hex');
      encrypted += cipher.final('hex');

      const authTag = cipher.getAuthTag();

      // Return salt, IV, ciphertext, and authentication tag together
      res.json({
        ciphertext: encrypted,
        salt: salt.toString('hex'),
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex')
      });
    } catch (e) {
      res.status(500).json({ error: 'Encryption failed' });
    }
  });
});

module.exports = router;
```

## Explanation

The fix replaces `crypto.createCipher()` (weak KDF, no authentication) with a two-step process:

1. **Key Derivation**: `crypto.pbkdf2()` derives a 32-byte (256-bit) key from the passphrase using 600,000 iterations with HMAC-SHA256. This is OWASP's recommended parameter set for PBKDF2 and is resistant to brute-force attacks on weak passphrases.

2. **Authenticated Encryption**: `crypto.createCipheriv('aes-256-gcm', key, iv)` replaces CBC mode with AES-256-GCM, which provides both confidentiality and authenticity. A fresh 12-byte IV is generated per request, and the authentication tag (from `cipher.getAuthTag()`) is returned alongside the ciphertext.

3. **Storage of Components**: The response now includes `salt`, `iv`, `ciphertext`, and `authTag` in hexadecimal. On decryption (not shown here), all four must be retrieved, the key re-derived using the same salt and PBKDF2 parameters, and the auth tag verified with `decipher.setAuthTag()` before calling `decipher.final()` to prevent padding-oracle and tampering attacks.

The fix eliminates both the weak key derivation (MD5 → PBKDF2) and the lack of authentication (CBC → GCM).

## Behaviour changes

- **New dependencies in response**: The API now returns `salt`, `iv`, and `authTag` alongside `ciphertext`. The client or storage layer must persist all four values together; encryption without the auth tag cannot be decrypted securely.
- **Async key derivation**: `crypto.pbkdf2()` is asynchronous. The encryption now happens in a callback, so the response is sent only after the key is derived and the cipher succeeds or fails.
- **Error handling**: Errors from `pbkdf2()` or cipher operations are now caught and reported as 500 errors instead of crashing the endpoint.
- **No silent failures**: If the passphrase is weak or the plaintext is large, the operation may take longer (PBKDF2 is deliberately slow to resist brute-force). This is intentional and improves security; the endpoint should not return a cached response before derivation completes.

On the decryption side (not shown), the receiver must:
1. Re-derive the key using the stored salt, the same passphrase, and the same PBKDF2 parameters.
2. Use `crypto.createDecipheriv('aes-256-gcm', key, iv)` with the stored IV.
3. Call `decipher.setAuthTag(authTag)` with the stored auth tag before `decipher.final()`.
4. Catch authentication failures (throw `ERR_CRYPTO_INVALID_AUTH_TAG` or `Unsupported state or unable to authenticate data`).
