## Verdict

exploitable (confidence: high)

## Source

`req.body.passphrase` and `req.body.body` in the `POST /notes/encrypt` handler (`CreateCipherLegacyApi.js`, lines 8-9) - both attacker-controlled request body fields, only null-checked (line 11) before use.

## Fix

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
const key = crypto.scryptSync(passphrase, salt, 32, {
  N: 131072, // 2^17, OWASP-recommended cost factor for scrypt
  r: 8,
  p: 1,
  maxmem: 134217728, // 128 MiB, required for N=2^17 (128 * N * r)
});
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

`crypto.createCipher('aes-256-cbc', passphrase)` is a listed taint sink: it derives both the key and the IV from the passphrase internally, using the legacy, unsalted, single-pass MD5-based EVP_BytesToKey scheme rather than a real key-derivation function, and it feeds an unauthenticated CBC mode - the pairing of a weak, deterministic key derivation with a MAC-less mode is exactly the class this CWE flags, and it was removed outright in Node 22. The fix separates the two responsibilities the sink was collapsing: `crypto.scryptSync(passphrase, salt, 32, ...)` derives a proper 32-byte key from the passphrase with a random salt and OWASP's scrypt cost parameters (N=2^17, with `maxmem` raised to the 128 MiB that cost requires, per the JavaScript guidance), and `crypto.createCipheriv('aes-256-gcm', key, iv)` with a fresh random 12-byte IV replaces the CBC cipher with an AEAD mode, so tampering is caught by `authTag` verification on decrypt instead of silently succeeding or opening a padding oracle.

## Behaviour changes

- Response payload gains `salt`, `iv`, and `authTag` fields alongside `ciphertext`. This is not incidental - AES-GCM requires the IV and auth tag to decrypt and verify, and passphrase-based scrypt derivation requires the salt to re-derive the same key; the original `createCipher` path had none of these because it derived a deterministic key+IV internally from the passphrase alone. Any corresponding decrypt endpoint must be updated to consume these fields (none exists in this file to update).
- Identical plaintext encrypted twice with the same passphrase now produces different ciphertext each time, because the salt and IV are freshly randomized per request. Under the original code, the same passphrase always derived the same key and IV, so the same plaintext always produced the same ciphertext - a key/IV-reuse weakness the fix also closes.
- The request now does more CPU work per call (`scryptSync` at OWASP's cost factor is intentionally expensive, and it runs synchronously, blocking the event loop for that duration). This is an intended consequence of hardening the key derivation, not incidental scope creep, but it does change the endpoint's latency/throughput profile under load.
