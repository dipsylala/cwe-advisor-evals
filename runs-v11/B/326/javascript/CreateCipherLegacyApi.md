## Verdict

Exploitable. The code uses `crypto.createCipher()` with a user-controlled passphrase, which is cryptographically weak and deprecated. This sink is listed in the CWE-326 JavaScript guidance's Taint Sinks section.

## Source

User-controlled `passphrase` parameter from HTTP request body (`req.body.passphrase`) at line 8, passed to the cipher at line 16.

## Fix

**Vulnerable code (line 16):**
```javascript
const cipher = crypto.createCipher('aes-256-cbc', passphrase);
```

**Fixed code:**
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

  // Generate a random salt and IV for each encryption
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);

  // Derive a key from the passphrase using PBKDF2 with OWASP recommended parameters
  crypto.pbkdf2(passphrase, salt, 600000, 32, 'sha256', (err, derivedKey) => {
    if (err) {
      return res.status(500).json({ error: 'Encryption failed' });
    }

    // Use AES-256-GCM (authenticated encryption) instead of CBC
    const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);

    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // Get the authentication tag for verified decryption
    const authTag = cipher.getAuthTag();

    // Return salt, IV, ciphertext, and auth tag (all needed for decryption and verification)
    res.json({
      salt: salt.toString('hex'),
      iv: iv.toString('hex'),
      ciphertext: encrypted,
      authTag: authTag.toString('hex')
    });
  });
});

module.exports = router;
```

## Explanation

The fix replaces `crypto.createCipher()` with `crypto.createCipheriv()` using AES-256-GCM, an authenticated encryption mode. The passphrase is no longer used directly as a key; instead, it is passed through `crypto.pbkdf2()` with OWASP-recommended parameters (600,000 iterations with SHA-256) to derive a cryptographically strong 32-byte key. A random 16-byte salt and 12-byte IV are generated for each encryption to ensure fresh, unpredictable values. GCM mode provides both confidentiality and authentication, preventing tampering attacks that CBC without a MAC is vulnerable to. The authentication tag is extracted and returned alongside the ciphertext; decryption code must verify this tag to ensure the message has not been modified.

## Behaviour changes

- **Key derivation**: The passphrase is now passed through PBKDF2 instead of being converted directly to a cipher key. This changes the derived key completely, so ciphertexts encrypted with the old code cannot be decrypted with the new code.
- **IV generation**: A random 12-byte IV is generated for each encryption instead of using the implicit IV handling of `createCipher()`. IVs must be stored alongside the ciphertext for decryption.
- **Response format**: The response now includes four fields (salt, IV, ciphertext, authTag) instead of a single ciphertext value. Decryption code must extract all four values and verify the tag before decryption.
- **Authentication**: The new code produces and returns an authentication tag via `getAuthTag()`. Decryption must call `setAuthTag()` before `final()` to verify the ciphertext has not been modified.
- **Error handling**: Key derivation is now asynchronous, so it is wrapped in a callback. If PBKDF2 fails, an error response is returned before cipher creation is attempted.
