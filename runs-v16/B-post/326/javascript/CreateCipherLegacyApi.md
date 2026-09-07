## Verdict
exploitable

## Source
`req.body.passphrase` (user-supplied passphrase from request body)

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

  // Generate random salt for key derivation
  const salt = crypto.randomBytes(16);
  
  // Derive a 32-byte key from the passphrase using PBKDF2-HMAC-SHA256
  const key = crypto.pbkdf2Sync(passphrase, salt, 600000, 32, 'sha256');
  
  // Generate a random 12-byte IV for this message
  const iv = crypto.randomBytes(12);
  
  // Use AES-256-GCM for authenticated encryption
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  // Get the authentication tag (critical for verifying integrity)
  const authTag = cipher.getAuthTag();

  // Return salt, IV, auth tag and ciphertext together so decryption can verify authenticity
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

The original code uses `crypto.createCipher()` with a passphrase, which is deprecated because it derives keys using weak MD5-based key derivation without a salt, making it vulnerable to dictionary attacks and password cracking. The CBC mode also lacks authentication, leaving it vulnerable to padding oracle attacks and ciphertext tampering.

The fix replaces this with a secure key derivation scheme: `crypto.pbkdf2Sync()` with 600,000 iterations (per OWASP for PBKDF2-HMAC-SHA256), a random salt, and authenticated encryption using AES-256-GCM. The authentication tag ensures the ciphertext has not been tampered with and must be verified during decryption before the plaintext is used. The salt and IV are returned with the ciphertext so they can be retrieved during decryption—they do not need to be kept secret, only random and unique per encryption operation (IV per message, salt typically per key).

## Behaviour changes

- **API change**: `crypto.createCipher()` replaced with `crypto.createCipheriv()` - requires an explicit IV parameter and algorithm specification.
- **Key derivation**: Passphrase is no longer used directly. It is now processed through PBKDF2 with 600,000 iterations and a random salt, producing a proper 32-byte key.
- **Cipher algorithm**: Changed from `aes-256-cbc` to `aes-256-gcm` to add authenticated encryption. GCM provides both confidentiality and integrity verification.
- **Random values**: Salt (16 bytes) and IV (12 bytes) are generated per encryption and must be stored/transmitted with the ciphertext.
- **Authentication tag**: `cipher.getAuthTag()` produces a 16-byte tag that must be stored with the ciphertext and verified during decryption via `decipher.setAuthTag()` before calling `final()`.
- **Output format**: The response now returns a JSON object with separate `salt`, `iv`, `authTag`, and `ciphertext` fields instead of a simple `ciphertext` field. This is necessary for the receiver to obtain all values needed for authenticated decryption.

The decryption side (not provided here but necessary for a complete fix) must:
1. Extract salt, IV, authTag, and ciphertext from the message
2. Use the passphrase with `crypto.pbkdf2Sync()` and the extracted salt to re-derive the same 32-byte key
3. Create a decipher with `crypto.createDecipheriv('aes-256-gcm', key, iv)`
4. Call `decipher.setAuthTag()` with the extracted auth tag before decryption
5. Call `decipher.update()` and `decipher.final()` to recover plaintext (throws `ERR_CRYPTO_INVALID_AUTH_TAG` if the tag does not match)
