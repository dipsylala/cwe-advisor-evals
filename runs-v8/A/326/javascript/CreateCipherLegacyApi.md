## Verdict

**CWE-326: Inadequate Encryption Strength - CONFIRMED**

The code uses `crypto.createCipher('aes-256-cbc', passphrase)`, which is deprecated and cryptographically weak. It derives the encryption key from the passphrase using MD5, an unsuitable hashing algorithm for key derivation that offers insufficient entropy and collision resistance for security-critical operations.

## Source

```javascript
const cipher = crypto.createCipher('aes-256-cbc', passphrase);
```

Node.js deprecated `createCipher` in v6.0.0 and marked it for removal because it does not use a salt and relies on MD5 for key derivation, both of which are cryptographically insufficient.

## Fix

Replace `createCipher` with `createCipheriv`, using PBKDF2 for proper key derivation:

```javascript
const crypto = require('crypto');

router.post('/notes/encrypt', (req, res) => {
  const passphrase = req.body.passphrase;
  const plaintext = req.body.body;

  if (!passphrase || !plaintext) {
    return res.status(400).json({ error: 'passphrase and body are required' });
  }

  // Generate a random 16-byte salt
  const salt = crypto.randomBytes(16);

  // Derive a 32-byte key using PBKDF2
  const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');

  // Generate a random 16-byte IV
  const iv = crypto.randomBytes(16);

  // Create cipher with the derived key and IV
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Prepend salt and IV to the ciphertext so decryption can retrieve them
  const result = salt.toString('hex') + ':' + iv.toString('hex') + ':' + encrypted;

  res.json({ ciphertext: result });
});
```

## Explanation

**Why this is a vulnerability**: `createCipher` derives keys using MD5 without a salt. MD5 is cryptographically broken and unsuitable for key derivation. An attacker can precompute keys for common passphrases much faster than legitimate users can derive them, enabling dictionary attacks. The absence of a salt means identical passphrases always produce identical keys across sessions, eliminating the semantic security that a random salt provides.

**How the fix works**:

1. **PBKDF2 key derivation**: `crypto.pbkdf2Sync()` with 100,000 iterations and SHA-256 derives a strong key from the passphrase. The iteration count makes brute-force attacks computationally expensive.

2. **Random salt**: Prevents precomputation attacks. Each encryption of the same plaintext with the same passphrase yields different ciphertext.

3. **Random IV**: Required for CBC mode to ensure identical plaintext blocks encrypt to different ciphertext. CBC with a fixed or reused IV is deterministic and leaks patterns.

4. **Prepending salt and IV**: The salt and IV are not secret and must be available for decryption. Prepending them to the ciphertext ensures the recipient can reconstruct the key and IV during decryption.

**Verification**: The ciphertext is now unique per encryption even with an identical passphrase, demonstrating that semantic security is restored.
