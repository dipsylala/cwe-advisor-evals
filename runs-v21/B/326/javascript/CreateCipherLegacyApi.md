## Verdict

Real issue. The finding is exploitable: `crypto.createCipher` uses weak key derivation from the passphrase alone, without a salt or random IV. The ciphertext is vulnerable to known-plaintext attacks and does not authenticate the message. The API is deprecated (end-of-life in Node 22) and must be replaced.

## Source

User-controlled passphrase from `req.body.passphrase` (line 8), used directly as key material in `crypto.createCipher` (line 16).

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

  // Generate random salt and IV for this encryption
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);

  // Derive a 32-byte key from the passphrase using PBKDF2 with SHA-256
  crypto.pbkdf2(passphrase, salt, 600000, 32, 'sha256', (err, derivedKey) => {
    if (err) {
      return res.status(500).json({ error: 'Encryption failed' });
    }

    // Use AES-256-GCM for authenticated encryption
    const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);

    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // Get authentication tag to verify integrity
    const authTag = cipher.getAuthTag();

    // Store all components needed for decryption
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

The fix replaces `crypto.createCipher` with `crypto.createCipheriv('aes-256-gcm', ...)` to use authenticated encryption. A random salt (16 bytes) and IV (12 bytes) are generated per message. The passphrase is passed through `crypto.pbkdf2()` with SHA-256, 600,000 iterations (OWASP standard for PBKDF2), and a salt to derive a strong 32-byte key, eliminating the weak implicit key derivation. AES-256-GCM provides both confidentiality and integrity; the authentication tag is stored and must be verified during decryption. The salt, IV, and auth tag are returned with the ciphertext so decryption can regenerate the key and verify authenticity. This closes the CWE-326 vulnerability by using an authenticated AEAD cipher with proper key derivation.

## Behaviour changes

- Response format changed to include `salt`, `iv`, and `authTag` alongside `ciphertext` (required for decryption and security verification).
- Encryption now asynchronous (callback-based) due to `pbkdf2` requiring a callback in this implementation pattern.
- Each message has a unique random IV, eliminating IV reuse.
- Decryption side must be updated to retrieve stored salt/IV/tag, call `pbkdf2` with the same salt and iterations, and call `setAuthTag()` before `final()` to verify authenticity.
