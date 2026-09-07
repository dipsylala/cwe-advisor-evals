## Verdict

The finding is **confirmed**. The code uses the deprecated `crypto.createCipher()` API, which derives encryption keys from passphrases using weak MD5 hashing without a salt. This provides inadequate key strength compared to modern key derivation best practices.

## Source

File: `CreateCipherLegacyApi.js`, line 16

The vulnerable sink:
```javascript
const cipher = crypto.createCipher('aes-256-cbc', passphrase);
```

The `crypto.createCipher()` method is explicitly deprecated in Node.js because it uses MD5 to derive the encryption key from the passphrase without a salt, making the key derivation weak and predictable.

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

  // Generate a random salt and IV for this encryption
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(16);

  // Derive a strong key from the passphrase using PBKDF2 with SHA256
  const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');

  // Use createCipheriv with explicit algorithm, key, and IV
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Prepend salt and IV to the ciphertext for decryption retrieval
  const result = salt.toString('hex') + ':' + iv.toString('hex') + ':' + encrypted;

  res.json({ ciphertext: result });
});

module.exports = router;
```

## Explanation

The remediation replaces the deprecated `createCipher()` API with proper, modern encryption practices:

1. **Random salt and IV generation**: Each encryption now uses fresh random values (`crypto.randomBytes()`), preventing attackers from deriving patterns across multiple encryptions of the same plaintext.

2. **PBKDF2 key derivation**: Replaces MD5-based key derivation with `crypto.pbkdf2Sync()` using SHA256, 100,000 iterations, and the random salt. This hardens the key derivation against dictionary and brute-force attacks.

3. **Explicit `createCipheriv()`**: Replaces the deprecated `createCipher()` with `createCipheriv()`, which requires explicitly specifying the algorithm, key, and IV. This prevents implicit weak defaults and makes the key material explicit in the code.

4. **Salt and IV embedding**: The salt and IV are prepended to the ciphertext output (separated by colons), allowing decryption to recover them. This pattern is standard because both values do not need to be secret—only the derived key does.

These changes ensure that the encryption strength matches the 256-bit AES algorithm in both key derivation and initialization vector entropy.
