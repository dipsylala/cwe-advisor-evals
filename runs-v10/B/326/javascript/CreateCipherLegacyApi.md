## Verdict

Exploitable. The `crypto.createCipher()` API uses MD5 to derive a key from the passphrase, which is cryptographically broken. Additionally, AES-256-CBC mode without authentication is vulnerable to padding oracle attacks. The passphrase is attacker-controlled (from `req.body.passphrase`) and reaches the insecure sink unvalidated.

## Source

- **Location**: E:/Github/cwe-advisor/evals/cases/326/javascript/CreateCipherLegacyApi/CreateCipherLegacyApi.js:16
- **Data origin**: `passphrase` from `req.body.passphrase` (user-supplied)
- **Sink**: `crypto.createCipher('aes-256-cbc', passphrase)`

## Fix

**Vulnerable code** (line 16):
```javascript
const cipher = crypto.createCipher('aes-256-cbc', passphrase);
```

**Fixed code**:
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

  // Generate random salt and IV
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);

  // Derive encryption key from passphrase using PBKDF2-HMAC-SHA256
  crypto.pbkdf2(passphrase, salt, 600000, 32, 'sha256', (err, derivedKey) => {
    if (err) {
      return res.status(500).json({ error: 'Key derivation failed' });
    }

    try {
      // Use AES-256-GCM with proper key derivation and random IV
      const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);
      
      let encrypted = cipher.update(plaintext, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      const authTag = cipher.getAuthTag();
      
      // Return salt, IV, auth tag, and ciphertext together for decryption
      res.json({
        salt: salt.toString('hex'),
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        ciphertext: encrypted
      });
    } catch (error) {
      res.status(500).json({ error: 'Encryption failed' });
    }
  });
});

module.exports = router;
```

## Explanation

`crypto.createCipher()` is deprecated and unsafe: it derives the encryption key using MD5, which is cryptographically broken, and uses a hardcoded IV derived from the key, allowing attackers to predict it. The fix replaces it with `crypto.createCipheriv()`, which accepts an explicit key and IV. The passphrase is now properly hashed using PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP's recommendation) and a random 32-byte salt. The cipher algorithm is changed to AES-256-GCM, which provides authenticated encryption: GCM detects tampering with ciphertext and fails decryption with `ERR_CRYPTO_INVALID_AUTH_TAG` on mismatch. The fix generates a fresh 12-byte random IV per encryption operation and returns the salt, IV, authentication tag, and ciphertext together so decryption can verify the tag with `decipher.setAuthTag()` before `decipher.final()`.

## Behaviour changes

1. **Async key derivation**: The original code was synchronous; the fix uses `crypto.pbkdf2()` with a callback, making key derivation asynchronous. This improves responsiveness on the event loop but requires restructuring the cipher operation into the callback. The original synchronous behaviour is not preserved.

2. **Return format changed**: The original returns only `ciphertext`; the fixed version returns an object with `salt`, `iv`, `authTag`, and `ciphertext`. The client must store all four values together and pass them back during decryption, or decryption will fail. This is required for authenticated decryption to work.

3. **Random salt and IV**: The original derives both from the passphrase deterministically. The fixed version generates cryptographically random salt and IV per request, so identical plaintexts encrypt to different ciphertexts. This is security-required for proper encryption.

4. **Authentication tag verification**: AES-GCM requires the tag to be verified on decryption with `decipher.setAuthTag()` before calling `decipher.final()`. The original code had no integrity checking; GCM's authentication is mandatory and non-optional here.

5. **Error handling**: The fixed code adds error handling for PBKDF2 derivation failures and cipher operations, returning 500 status on failure where the original had no error path.

