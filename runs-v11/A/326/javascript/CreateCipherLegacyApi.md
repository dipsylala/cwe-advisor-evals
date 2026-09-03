## Verdict

CWE-326: Inadequate Encryption Strength — `crypto.createCipher()` is deprecated and uses weak key derivation without a salt, making the encryption vulnerable to dictionary attacks and rainbow tables.

## Source

```javascript
const cipher = crypto.createCipher('aes-256-cbc', passphrase);
```

## Fix

```javascript
const crypto = require('crypto');

// Generate a random salt (or derive from a known value stored per user)
const salt = crypto.randomBytes(16);

// Derive a strong encryption key from the passphrase using PBKDF2
crypto.pbkdf2(passphrase, salt, 100000, 32, 'sha256', (err, derivedKey) => {
  if (err) {
    return res.status(500).json({ error: 'Encryption key derivation failed' });
  }

  // Generate a random IV for this message
  const iv = crypto.randomBytes(16);

  // Create cipher with derived key and IV
  const cipher = crypto.createCipheriv('aes-256-cbc', derivedKey, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Return salt and IV with ciphertext (salt and IV do not need to be secret)
  res.json({ salt: salt.toString('hex'), iv: iv.toString('hex'), ciphertext: encrypted });
});
```

For decryption, extract the salt and IV from the response, re-derive the key using the same salt and passphrase, then use `crypto.createDecipheriv()` with the extracted IV.

## Explanation

`crypto.createCipher()` derives keys using EVP_BytesToKey, which does not use a salt and produces deterministic output for the same passphrase. This allows an attacker to precompute hashes of common passphrases (rainbow table attack) and match them against intercepted ciphertexts.

The fix uses:
- **PBKDF2** with a random salt (100,000 iterations, SHA-256) to derive a strong key from the passphrase, making precomputation infeasible
- **Random IV** (initialization vector) for each encryption to prevent identical plaintexts producing identical ciphertexts
- **`crypto.createCipheriv()`** which is the modern, maintained API that accepts an explicit key and IV

Both salt and IV are transmitted with the ciphertext (they are not secret). Only the derived key remains secret.
