## Verdict

- **cwe_id**: CWE-326 (Inadequate Encryption Strength)
- **location**: `CreateCipherLegacyApi.js:16`
- **verdict**: exploitable
- **confidence**: high

## Source

- **source**: `req.body.passphrase` (client-supplied encryption passphrase) and `req.body.body` (client-supplied plaintext), both read at lines 8-9 with only a presence check (line 11) before use - no strength or format constraint on the passphrase.
- **sink**: `crypto.createCipher('aes-256-cbc', passphrase)` at line 16.
- **flow**: `passphrase` reaches `createCipher` unmodified. `createCipher` does not accept a key directly - it derives both the AES key and the IV from the passphrase internally using OpenSSL's `EVP_BytesToKey`, a single unsalted round of MD5. This is the finding: the key-derivation step feeding the cipher is weak (unsalted, one round, fast hash) and the IV is deterministic (same passphrase -> same IV), which is a nonce-reuse/IV-reuse weakness for CBC mode on top of the weak KDF. The algorithm name `'aes-256-cbc'` itself is not the problem; the deprecated derivation path `createCipher` uses to turn the passphrase into key material is. `crypto.createCipher(` is a listed taint sink in `cwe/326/javascript/INDEX.md`, and `createCipher` (no IV) is end-of-life and removed starting Node 22.

## Fix

No external library is needed - Node's built-in `crypto` module already provides the safe replacement (`scrypt` for key derivation, `createCipheriv` with an AEAD mode).

Vulnerable code:
```javascript
// SAST FINDING: CWE-326 (Inadequate Encryption Strength) reported here. Sink is the next statement.
const cipher = crypto.createCipher('aes-256-cbc', passphrase);

let encrypted = cipher.update(plaintext, 'utf8', 'hex');
encrypted += cipher.final('hex');

res.json({ ciphertext: encrypted });
```

Fixed code:
```javascript
const salt = crypto.randomBytes(16);
const key = crypto.scryptSync(passphrase, salt, 32);
const iv = crypto.randomBytes(12);

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
```

## Explanation

`createCipher` is replaced with `createCipheriv('aes-256-gcm', ...)` fed by key material that is derived explicitly rather than implicitly. A random 16-byte salt is generated per request and passed through `crypto.scryptSync(passphrase, salt, 32)` to derive a 32-byte key - `scryptSync`'s default cost parameters (N=16384, r=8, p=1) are memory-hard and salted, unlike the single round of unsalted MD5 that `createCipher` used internally, so the same passphrase no longer collapses to the same key across requests. A fresh 12-byte IV is generated with `crypto.randomBytes(12)` (GCM's recommended nonce length) instead of being derived deterministically from the passphrase, closing the IV-reuse weakness. Switching the mode from CBC to GCM also moves the cipher to an authenticated construction: `cipher.getAuthTag()` is captured after `final()` so a tampered ciphertext can be detected on decryption via `decipher.setAuthTag()` failing, whereas plain CBC gave no integrity guarantee at all.

## Behaviour changes

- **Response now includes `salt`, `iv`, and `authTag` alongside `ciphertext`.** Reason: `createCipher` derived both key and IV from the passphrase alone, so the original response needed to carry only the ciphertext - decryption could reconstruct the key/IV from the same passphrase with no other material. The fixed code derives the key from a per-request random salt and uses a per-request random IV, both required by GCM decryption; the auth tag is likewise required by `setAuthTag()` before `decipher.final()`. Without exposing these three values, the ciphertext could never be decrypted again, which would just trade the encryption-strength defect for a different bug (undecryptable data). This is a necessary consequence of closing the weakness, not scope creep, since the sink's contract (produce output the caller can later decrypt) can only be preserved by carrying this material forward.
- Everything else - the 400 validation branch, the request/response shape's `ciphertext` field, `utf8`/`hex` encodings, and the overall control flow - is unchanged.
- **Assumption**: the deployment runs a Node.js version where `crypto.createCipher` still executes (it is removed starting Node 22, in which case the reported line would already throw rather than run). This does not change the fix - the replacement is required either way - but is noted since it affects how directly line 16 is reachable at runtime, per Step 4 of the CWE Advisor's guidance on checking the Node version before treating a sink as live.
