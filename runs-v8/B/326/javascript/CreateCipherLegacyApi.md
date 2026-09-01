## Verdict

**VULNERABLE** — CWE-326 confirmed at line 16.

## Source

The vulnerability originates at line 8 with attacker-controlled input `req.body.passphrase` and flows to line 16 where it is used as a parameter to `crypto.createCipher()`.

```javascript
const passphrase = req.body.passphrase;  // Line 8: untrusted source
// ...
const cipher = crypto.createCipher('aes-256-cbc', passphrase);  // Line 16: weak sink
```

## Fix

Replace `crypto.createCipher()` with `crypto.createCipheriv()` using proper key derivation and authenticated encryption:

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

  // Generate a random salt for key derivation
  const salt = crypto.randomBytes(16);
  
  // Derive a key from the passphrase using scrypt (OWASP-recommended defaults)
  const key = crypto.scryptSync(passphrase, salt, 32);
  
  // Generate a random IV for this message
  const iv = crypto.randomBytes(12);
  
  // Create cipher using aes-256-gcm with the derived key
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  // Get the authentication tag
  const authTag = cipher.getAuthTag();

  // Return salt, iv, authTag, and ciphertext together
  res.json({ 
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
    ciphertext: encrypted 
  });
});

module.exports = router;
```

## Explanation

The fix replaces `crypto.createCipher()` (deprecated, weak KDF) with `crypto.createCipheriv()` (explicit IV, strong KDF). Three changes eliminate the weakness:

1. **Proper key derivation**: `crypto.scrypt()` with a random salt replaces the implicit MD5-based KDF. Scrypt uses OWASP-recommended defaults (N=2^14, r=8, p=1) and produces a 32-byte key suitable for AES-256.

2. **Authenticated encryption**: AES-256-GCM replaces CBC mode, providing both confidentiality and integrity. The `getAuthTag()` value must be stored and transmitted with the ciphertext so the recipient can verify authenticity during decryption and detect tampering.

3. **Explicit IV**: A fresh random 12-byte IV is generated per message, eliminating the risk of IV reuse across plaintexts. The IV must be stored alongside the ciphertext (as shown in the response object).

The decryption side must reverse this: use the stored salt to re-derive the key from the passphrase, reconstruct the cipher with the stored IV, and call `decipher.setAuthTag(tag)` before `decipher.final()` to authenticate the ciphertext and reject tampered data.

## Behaviour changes

**Output format changed**: The response previously returned only `{ciphertext: encrypted}`. It now returns `{salt, iv, authTag, ciphertext}` — all necessary to decrypt. Clients must be updated to extract and store all four components and send them back on decryption requests.

**Key derivation added latency**: `crypto.scryptSync()` is intentionally slow (a feature for password stretching). For high-throughput encryption with a single passphrase, consider deriving the key once at server startup and caching it, rather than re-deriving on each request. The salt then becomes a one-time constant (stored and included in comments), not a per-message random value.

**Decryption contract changed**: Decryption endpoints not shown here must now accept salt, IV, authTag, and ciphertext separately, reconstruct the key using the salt, and call `setAuthTag()` before `final()`. Any omitted or altered component causes authentication to fail with `ERR_CRYPTO_INVALID_AUTH_TAG`, which is the correct behaviour — a critical security property that CBC mode lacked.
