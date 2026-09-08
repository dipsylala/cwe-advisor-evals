## Verdict

exploitable

- cwe_id: CWE-326
- location: CreateCipherLegacyApi.js, line 16 (sink), lines 8-9 (source)
- confidence: high

## Source

`req.body.passphrase` and `req.body.body`, read from the Express request handler at `router.post('/notes/encrypt', ...)`. Both are attacker/client-controlled and flow unmodified (only null-checked, not transformed) into the sink three lines later.

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

  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(passphrase, salt, 32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();

  res.json({
    ciphertext: encrypted,
    iv: iv.toString('hex'),
    salt: salt.toString('hex'),
    authTag: authTag.toString('hex'),
  });
});

module.exports = router;
```

## Explanation

`crypto.createCipher('aes-256-cbc', passphrase)` derives its key and IV from the passphrase using OpenSSL's legacy `EVP_BytesToKey` (a single unsalted MD5 pass), reuses the same IV for every message encrypted under a given passphrase, and provides no integrity check - CBC without a MAC verified before decryption is a padding-oracle vector, not just a weaker mode. The fix replaces it with `crypto.createCipheriv('aes-256-gcm', key, iv)`, where the key is derived with `crypto.scryptSync(passphrase, salt, 32)` over a fresh random 16-byte salt (`crypto.randomBytes(16)`) and the cipher uses a fresh random 12-byte IV (`crypto.randomBytes(12)`) per call, matching `aes-256-gcm`'s required 32-byte key. `scryptSync` is used with its documented defaults (`cost` 16384, `blockSize` 8, `parallelization` 1), which stay under the default 32 MiB `maxmem` ceiling, so no `maxmem` override is needed. GCM is an AEAD mode, so `cipher.getAuthTag()` is captured after `final()` and returned alongside the ciphertext; a decrypting party must pass the same salt, IV and tag to `decipher.setAuthTag()` before `decipher.final()`, which throws on any tampering or wrong key. This closes the weak-primitive finding (CWE-326) via the language guidance's prescribed replacement (`aes-256-gcm` over `createCipheriv`) rather than only the general recommendation.

## Behaviour changes

- Response body gains `iv`, `salt`, and `authTag` fields (hex-encoded) alongside the existing `ciphertext`. Reason: GCM requires a per-message IV and an auth tag, and the key is now salted, none of which `createCipher`'s implicit derivation exposed or needed; without these three values stored alongside the ciphertext, the note can never be decrypted again. This is a required, unavoidable consequence of moving off the broken implicit key/IV derivation - there is no way to make an AEAD cipher decryptable later without persisting its IV and tag, and no way to reproduce the key later without persisting the salt used to derive it.
- Ciphertext value differs from the original for the same input, because the key derivation, IV, and cipher mode all changed. Reason: this is the entire point of the fix - the old scheme derived a deterministic, unsalted key/IV pair from the passphrase alone.
- No change to error handling, status codes, or the `400` validation branch - that logic is untouched.

## Verification

- `node --check` on the fixed file: passed with no diagnostics (checked from a scratch copy outside the repository).
- Functional smoke test (scratch script, not the case file): ran the fix's encrypt logic standalone, then decrypted with `crypto.createDecipheriv('aes-256-gcm', ...)` using the returned salt/iv/authTag and confirmed the round-tripped plaintext matched exactly. A second run flipped a byte of the ciphertext and confirmed `decipher.final()` throws `Unsupported state or unable to authenticate data` rather than returning tampered plaintext, verifying the AEAD integrity check is live.
- Every new API used (`crypto.randomBytes`, `crypto.scryptSync`, `crypto.createCipheriv`, `cipher.getAuthTag`) is named explicitly in the loaded `cwe/326/javascript/INDEX.md` guidance and is part of Node's core `crypto` module; none required an assumption.
