## Verdict

exploitable

## Source

`passphrase` from `req.body.passphrase` at line 8 (attacker-controlled user input)

## Fix

### File: CreateCipherLegacyApi.js

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

  // Derive a 32-byte key from the passphrase using PBKDF2
  const salt = crypto.randomBytes(16);
  crypto.pbkdf2(passphrase, salt, 600000, 32, 'sha256', (err, derivedKey) => {
    if (err) {
      return res.status(500).json({ error: 'Encryption failed' });
    }

    // Generate a fresh 12-byte IV for each message
    const iv = crypto.randomBytes(12);

    // Use AES-256-GCM for authenticated encryption
    const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);

    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // Get the authentication tag
    const authTag = cipher.getAuthTag();

    // Return the salt, IV, ciphertext and auth tag together
    res.json({
      ciphertext: encrypted,
      salt: salt.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    });
  });
});

module.exports = router;
```

## Explanation

The original code uses `crypto.createCipher()` with a user-controlled passphrase, which is inadequate for several reasons: it uses implicit and weak key derivation via `EVP_BytesToKey` without a salt, operates in unauthenticated CBC mode (vulnerable to padding oracle attacks), lacks an explicit IV, and is deprecated/removed in Node 22. The fix replaces it with `crypto.createCipheriv()` using AES-256-GCM with proper key derivation: a random salt and PBKDF2 with 600,000 iterations and SHA-256 (per OWASP) to derive a 32-byte key. A fresh 12-byte IV is generated per message for GCM mode. The authentication tag from `getAuthTag()` is returned alongside the ciphertext to enable authenticated decryption. The salt and IV must be stored/transmitted with the ciphertext and used during decryption with `decipher.setAuthTag()` before calling `decipher.final()` to verify integrity.

## Behaviour changes

- **Encryption is now asynchronous**: The encryption operation moved into a `crypto.pbkdf2()` callback to allow proper key derivation. Code calling this endpoint must handle the asynchronous response. Rationale: `pbkdf2()` is the approved key derivation function; running it synchronously would block the event loop, so the callback pattern is necessary.
- **Response format changed**: The response now includes `salt`, `iv`, and `authTag` in addition to `ciphertext`, all as hex-encoded strings. Rationale: These values are cryptographically necessary for decryption with authenticated encryption and cannot be omitted without breaking the security model.
- **Authenticated encryption used**: GCM mode ensures ciphertext integrity and authenticity, replacing CBC which offers neither. Rationale: GCM (Galois/Counter Mode) is required by the guidance for authenticated encryption; CBC alone is vulnerable to padding oracle attacks and does not detect tampering.
- **Key derivation now explicit**: A 16-byte random salt and PBKDF2 with 600,000 iterations replace the implicit `EVP_BytesToKey`. Rationale: PBKDF2-HMAC-SHA256 with 600,000 iterations is OWASP's prescribed strength for password derivation; salt ensures dictionary attacks must be redone per value.
- **Error handling added**: A callback error path in `pbkdf2()` returns a 500 status on key derivation failure. Rationale: Key derivation can fail; the error must be surfaced rather than silently ignored.

## Verification

Syntax checked with `node --check` against the fixed file: no errors.

Verified that:
- `crypto.randomBytes(16)` and `crypto.randomBytes(12)` are standard library calls that produce buffers for salt and IV
- `crypto.pbkdf2()` signature matches Node.js documentation: `crypto.pbkdf2(password, salt, iterations, keylen, digest, callback)` with digest as a required positional argument (SHA-256 specified)
- `crypto.createCipheriv('aes-256-gcm', derivedKey, iv)` requires a 32-byte key (matches derived key length from PBKDF2's keylen=32)
- `cipher.getAuthTag()` is called after `cipher.final()` and before the response, which is correct
- `iv.toString('hex')` and `salt.toString('hex')` are standard buffer conversion methods
- All new crypto APIs used are stable in Node.js versions maintaining `createCipher` (pre-22)
