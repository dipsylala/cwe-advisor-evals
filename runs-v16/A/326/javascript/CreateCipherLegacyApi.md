## Verdict

Real vulnerability. `crypto.createCipher()` is a deprecated legacy API that derives encryption keys using MD5, a cryptographically broken hash function, without salt. This results in inadequate encryption strength.

## Source

```javascript
const cipher = crypto.createCipher('aes-256-cbc', passphrase);
```

Line 16 of CreateCipherLegacyApi.js uses the deprecated `crypto.createCipher()` method.

## Fix

Replace the deprecated `createCipher()` call with `createCipheriv()`, which accepts an explicit key and initialization vector derived using a strong key derivation function:

```javascript
const crypto = require('crypto');

// At the start of the route handler:
const passphrase = req.body.passphrase;
const plaintext = req.body.body;

if (!passphrase || !plaintext) {
  return res.status(400).json({ error: 'passphrase and body are required' });
}

// Generate a random salt (16 bytes is standard)
const salt = crypto.randomBytes(16);

// Derive key using PBKDF2 with SHA-256 (256 bits for AES-256)
const key = crypto.pbkdfSync(passphrase, salt, 100000, 32, 'sha256');

// Generate a random IV (16 bytes for CBC mode)
const iv = crypto.randomBytes(16);

// Create cipher with derived key and IV
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

let encrypted = cipher.update(plaintext, 'utf8', 'hex');
encrypted += cipher.final('hex');

// Prepend salt and IV to ciphertext so they can be recovered during decryption
const ciphertext = salt.toString('hex') + iv.toString('hex') + encrypted;

res.json({ ciphertext: ciphertext });
```

## Explanation

`crypto.createCipher()` is deprecated because it derives the encryption key using MD5 and the passphrase alone, with no salt and a single iteration. This approach has multiple weaknesses:

1. **Weak key derivation**: MD5 is cryptographically broken and unsuitable for further use.
2. **No salt**: Without a salt, identical passphrases always produce identical keys, enabling rainbow table attacks.
3. **Insufficient iterations**: The hardcoded single iteration provides no protection against brute-force attacks.

The fix uses `crypto.createCipheriv()` with explicit key derivation via `crypto.pbkdfSync()`, which uses PBKDF2 with SHA-256, a random salt, and 100,000 iterations. This provides:

- A cryptographically secure key derivation function
- A unique salt per encryption, preventing rainbow tables
- Multiple iterations to resist brute-force attacks
- Explicit control over the IV, ensuring randomness

The salt and IV are prepended to the ciphertext unencrypted, which is standard practice—they only need to be unique, not secret.
