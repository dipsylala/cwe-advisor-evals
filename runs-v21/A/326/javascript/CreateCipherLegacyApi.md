## Verdict

CONFIRMED: CWE-326 — Inadequate Encryption Strength via legacy `createCipher` API.

## Source

The vulnerability originates from user-supplied `passphrase` (line 8, `req.body.passphrase`) and `plaintext` (line 9, `req.body.body`).

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

  // Use a proper key derivation function with a random salt
  const salt = crypto.randomBytes(32);
  const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');

  // Use createCipheriv with a random IV instead of the legacy createCipher
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Include IV and salt in the response so they can be used for decryption
  res.json({ 
    ciphertext: encrypted,
    iv: iv.toString('hex'),
    salt: salt.toString('hex')
  });
});

module.exports = router;
```

## Explanation

The original code used `crypto.createCipher()`, which is deprecated and cryptographically weak because it derives both the key and IV from the passphrase using an outdated EVP_BytesToKey function. This violates CWE-326 by using inadequate encryption strength.

The fix replaces this with:

1. **Proper key derivation**: `crypto.pbkdf2Sync()` derives a 256-bit key from the passphrase using 100,000 iterations and SHA-256, making brute-force attacks computationally infeasible.
2. **Random IV**: `crypto.randomBytes(16)` generates a cryptographically secure 16-byte IV for each encryption, preventing deterministic ciphertext.
3. **Random salt**: A 32-byte salt is generated for each operation to prevent rainbow table attacks and ensure the derived key is unique per encryption.
4. **Modern API**: `crypto.createCipheriv()` provides explicit control over the key and IV, following NIST standards.
5. **IV and salt transport**: Both are returned to the client as hex strings, necessary for decryption. These values are public and do not compromise security.

This approach provides strong encryption suitable for production use and aligns with modern cryptographic best practices.
