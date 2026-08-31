## Verdict
Confirmed. `crypto.createCipher('aes-256-cbc', passphrase)` uses Node's deprecated legacy cipher API, which derives the key from the passphrase with a single round of unsalted MD5 (`EVP_BytesToKey`) and uses an all-zero implicit IV. Both properties make the encryption weak: the key derivation is fast to brute-force and identical passphrases always produce the same key/IV pair, leaking plaintext structure across messages (CWE-326).

## Source
`req.body.passphrase` and `req.body.body`, from the POST body of `/notes/encrypt` — both attacker/client-supplied. `passphrase` flows unmodified into the sink at line 16.

## Fix
```javascript
const express = require('express');
const crypto = require('crypto');

const router = express.Router();

const SALT_LENGTH = 16;
const IV_LENGTH = 12; // GCM standard nonce size
const KEY_LENGTH = 32; // 256-bit key for aes-256-gcm

// Encrypts a note's body using a passphrase supplied by the client.
router.post('/notes/encrypt', (req, res) => {
  const passphrase = req.body.passphrase;
  const plaintext = req.body.body;

  if (!passphrase || !plaintext) {
    return res.status(400).json({ error: 'passphrase and body are required' });
  }

  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);

  // scrypt derives a proper key from the passphrase with a random, per-message salt.
  const key = crypto.scryptSync(passphrase, salt, KEY_LENGTH);

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

module.exports = router;
```

## Explanation
`crypto.createCipher()` was deprecated in Node.js v10 and removed entirely in v22 because it relies on `EVP_BytesToKey`, an OpenSSL legacy key-derivation routine that runs MD5 exactly once over the passphrase with no salt, and it hard-codes the IV to all zeros. That means the same passphrase always yields the same key and IV, so identical or related plaintexts encrypt to identical or related ciphertext prefixes (a classic IV-reuse leak with CBC mode), and the unsalted single-MD5 derivation is orders of magnitude cheaper to brute-force offline than a proper password-based KDF.

The fix replaces the sink with `crypto.createCipheriv()`, Node's supported, non-deprecated cipher constructor, which requires the caller to supply the key and IV explicitly rather than deriving them internally. The key is derived with `crypto.scryptSync()` (memory-hard, tunable, and the KDF Node's own docs recommend for this exact passphrase-to-key use case) using a fresh random salt generated per request. The IV is also freshly randomized per request via `crypto.randomBytes()`, eliminating the IV-reuse issue. The mode is switched from `aes-256-cbc` to `aes-256-gcm`, an authenticated mode, so the response also returns the generated `authTag`; this adds integrity/tamper detection that CBC alone does not provide and is a natural companion fix when already touching the cipher call, though the core CWE-326 issue is the key/IV derivation, not the mode choice itself. The salt, IV, and auth tag must all be returned (or stored) alongside the ciphertext, since decryption cannot succeed without them — none of the three needs to be kept secret; only the passphrase and derived key do.

Verification: decrypt the returned ciphertext using `crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'))` with the key re-derived via `scryptSync(passphrase, Buffer.from(salt, 'hex'), 32)`, call `setAuthTag(Buffer.from(authTag, 'hex'))`, and confirm the recovered plaintext matches the original. Also confirm that two identical requests (same passphrase and body) now produce different `ciphertext`, `salt`, and `iv` values each time, proving the IV-reuse and static-derivation weaknesses are closed.
