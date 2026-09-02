## Verdict

Confirmed. `crypto.createCipher('aes-256-cbc', passphrase)` uses Node's deprecated single-argument cipher API, which derives the AES key from the passphrase via `EVP_BytesToKey` (a single round of unsalted MD5) and derives the initialization vector deterministically from that same digest instead of using a random IV. Both properties are cryptographic weaknesses independent of the AES-256 cipher itself: the MD5-based, unsalted key derivation is fast to brute-force and identical passphrases always yield identical keys, and the deterministic IV means identical plaintext prefixes always produce identical ciphertext prefixes under the same passphrase, leaking structure (CWE-326 / effectively CWE-329 IV reuse layered on top of a weak KDF).

## Source

`req.body.passphrase` and `req.body.body`, taken directly from the incoming POST request in `router.post('/notes/encrypt', ...)`, flow unmodified into `crypto.createCipher('aes-256-cbc', passphrase)` at line 16.

## Fix

```javascript
const express = require('express');
const crypto = require('crypto');

const router = express.Router();

const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const KEY_LENGTH = 32; // 256-bit key for aes-256-gcm
const SCRYPT_PARAMS = { N: 2 ** 15, r: 8, p: 1 };

// Encrypts a note's body using a passphrase supplied by the client.
router.post('/notes/encrypt', (req, res) => {
  const passphrase = req.body.passphrase;
  const plaintext = req.body.body;

  if (!passphrase || !plaintext) {
    return res.status(400).json({ error: 'passphrase and body are required' });
  }

  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);

  crypto.scrypt(passphrase, salt, KEY_LENGTH, SCRYPT_PARAMS, (err, key) => {
    if (err) {
      return res.status(500).json({ error: 'encryption failed' });
    }

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    res.json({
      ciphertext: encrypted,
      salt: salt.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
    });
  });
});

module.exports = router;
```

## Explanation

The fix replaces `crypto.createCipher` with `crypto.createCipheriv`, which requires the key and IV to be supplied explicitly rather than derived internally by the weak, undocumented `EVP_BytesToKey` routine. Two independent problems are corrected:

- **Key derivation**: the passphrase is now run through `crypto.scrypt` with a per-request random 16-byte salt and CPU/memory-hard parameters (`N=2^15, r=8, p=1`, tunable to the deployment's latency budget), producing a 32-byte key suitable for AES-256. `scrypt` is deliberately expensive to brute-force, unlike the single unsalted MD5 pass `createCipher` used internally, and the random salt means two identical passphrases no longer yield identical keys.
- **IV handling**: a fresh, cryptographically random 12-byte IV is generated with `crypto.randomBytes` for every encryption call instead of being derived deterministically from the passphrase digest, eliminating the identical-plaintext-produces-identical-ciphertext leakage.

The cipher mode is also changed from `aes-256-cbc` to `aes-256-gcm`. This is not strictly required to close the CWE-326 finding, but pairs naturally with the `createCipheriv` migration: GCM is an authenticated (AEAD) mode, so `cipher.getAuthTag()` produces a tag that must be verified on decryption, protecting the ciphertext against tampering — a property CBC does not provide and that a manual HMAC would otherwise need to be bolted on separately.

Because the key derivation is no longer implicit, the salt and IV must now be persisted alongside the ciphertext (returned in the response here) so the corresponding decryption path can reproduce the same key via `crypto.scryptSync`/`scrypt` with the stored salt, and re-run `createDecipheriv('aes-256-gcm', key, iv)` with the stored `authTag` set via `setAuthTag` before decrypting. Verify the fix by round-tripping a known plaintext/passphrase through encrypt and decrypt, and by confirming that encrypting the same plaintext with the same passphrase twice now produces two different ciphertexts (different salt and IV each time), unlike the original code.
