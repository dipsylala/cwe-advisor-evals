## Verdict

Confirmed. `crypto.createCipher('aes-256-cbc', passphrase)` at line 16 uses Node's legacy key-derivation path: it derives the AES key (and IV) from the passphrase with a single round of unsalted MD5 (OpenSSL's `EVP_BytesToKey`), and it reuses a fixed, all-zero IV for every message. Unsalted single-round MD5 makes the derived key trivially crackable/rainbow-tableable, and a constant IV under CBC means any two notes encrypted with the same passphrase leak whether their leading plaintext blocks are identical (and enables chosen-plaintext attacks). This is exactly the case `createCipher`/`createDecipher` were deprecated for; both are legacy APIs that route through this weak KDF and are unsuitable for producing an encryption strength adequate for confidentiality of user data.

## Source

`req.body.passphrase` and `req.body.body`, read at lines 8-9 of `router.post('/notes/encrypt', ...)`, flow unmodified into `crypto.createCipher('aes-256-cbc', passphrase)` at line 16, which is the sink.

## Fix

### File: CreateCipherLegacyApi.js

```javascript
const express = require('express');
const crypto = require('crypto');

const router = express.Router();

const SCRYPT_KEY_LENGTH = 32; // 256-bit key for aes-256-cbc
const SALT_LENGTH = 16;
const IV_LENGTH = 16;

// Encrypts a note's body using a passphrase supplied by the client.
router.post('/notes/encrypt', (req, res) => {
  const passphrase = req.body.passphrase;
  const plaintext = req.body.body;

  if (!passphrase || !plaintext) {
    return res.status(400).json({ error: 'passphrase and body are required' });
  }

  // Derive a strong per-message key from the passphrase with scrypt (salted,
  // memory-hard) instead of createCipher's implicit unsalted single-round MD5,
  // and use a fresh random IV instead of createCipher's fixed all-zero IV.
  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = crypto.scryptSync(passphrase, salt, SCRYPT_KEY_LENGTH);

  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // salt and iv are not secret; the recipient needs them to derive the same
  // key and decrypt, so they are returned alongside the ciphertext.
  res.json({
    ciphertext: encrypted,
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
  });
});

module.exports = router;
```

## Explanation

The fix replaces `crypto.createCipher` with `crypto.createCipheriv`, which requires the caller to supply the key and IV explicitly rather than deriving them internally through the weak legacy path. The key is derived with `crypto.scryptSync`, a memory-hard KDF, salted with 16 bytes of `crypto.randomBytes` generated fresh per request, so two notes encrypted with the same passphrase produce unrelated keys and the derivation resists brute-force/rainbow-table attacks far better than a single MD5 round. A fresh random 16-byte IV is generated per request and passed to `createCipheriv`, eliminating the fixed-IV pattern-leakage weakness of `createCipher`. Because decryption needs the same salt and IV to reproduce the key and initialize the cipher, both are returned (hex-encoded) alongside the ciphertext; they are not secret and their disclosure does not weaken the scheme, unlike the passphrase itself. The output shape changes (two new non-secret fields), which is the minimal breaking change required to make decryption possible at all under a proper per-message key/IV scheme; any legitimate consumer of this endpoint must already be updated to a corresponding fix on the decrypt side that also moves off `createDecipher`.
