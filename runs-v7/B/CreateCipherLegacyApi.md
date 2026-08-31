## Verdict

Real. Line 16 uses `crypto.createCipher()` with CBC mode and implicit key derivation, both deprecated patterns for encryption strength. The API is end-of-life in Node 22, and CBC without authentication is a padding-oracle vector.

## Source

Line 8: `const passphrase = req.body.passphrase;` — untrusted user input.
Line 16: `crypto.createCipher('aes-256-cbc', passphrase)` — sink that applies weak encryption with no IV and no authentication tag.

The passphrase flows directly from the request body to the deprecated cipher without key derivation or authenticated encryption.

## Fix

Replace the cipher initialization and encryption logic:

**Vulnerable code (line 16-19):**
```javascript
const cipher = crypto.createCipher('aes-256-cbc', passphrase);
let encrypted = cipher.update(plaintext, 'utf8', 'hex');
encrypted += cipher.final('hex');
```

**Fixed code:**
```javascript
// Derive key from passphrase using PBKDF2
const salt = crypto.randomBytes(16);
const key = crypto.pbkdf2Sync(passphrase, salt, 600000, 32, 'sha256');

// Generate a random IV for this message
const iv = crypto.randomBytes(12);

// Use authenticated encryption (AES-256-GCM)
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
let encrypted = cipher.update(plaintext, 'utf8', 'hex');
encrypted += cipher.final('hex');
const authTag = cipher.getAuthTag();

// Return salt, IV, ciphertext, and authentication tag together
res.json({ 
  ciphertext: encrypted,
  iv: iv.toString('hex'),
  salt: salt.toString('hex'),
  authTag: authTag.toString('hex')
});
```

The decryption side must:
1. Parse the stored salt, IV, and authTag
2. Derive the same key: `crypto.pbkdf2Sync(passphrase, Buffer.from(salt, 'hex'), 600000, 32, 'sha256')`
3. Create a decipher with the same IV: `crypto.createDecipheriv('aes-256-gcm', key, iv)`
4. Call `decipher.setAuthTag(Buffer.from(authTag, 'hex'))` before `decipher.final()` to verify authentication

## Explanation

The fix addresses three CWE-326 weaknesses:

1. **Authenticated encryption**: Replaces CBC (unauthenticated) with GCM, which provides both confidentiality and authentication. Without authentication, a padding oracle attack can decrypt without the key. The authentication tag is mandatory on decryption via `setAuthTag()` before calling `final()`, which throws if the ciphertext or tag was tampered with.

2. **Proper key derivation**: Replaces `createCipher`'s deprecated EVP_BytesToKey with PBKDF2-HMAC-SHA256 at 600,000 iterations (OWASP standard for FIPS-140 compliance). The salt is generated randomly per encryption and stored with the ciphertext so decryption can re-derive the same key.

3. **Initialization vector**: Replaces implicit derivation with explicit 12-byte random IV generated per message. A fresh IV is critical for GCM security; reusing the same IV with the same key is a fatal flaw that leaks the plaintext XOR stream.

The API change from `createCipher` (deprecated, removed in Node 22) to `createCipheriv` is required to use modern ciphers. The fix closes the padding-oracle vector and removes reliance on a deprecated key derivation.

## Behaviour changes

**Storage format changes**: The response now includes `iv`, `salt`, and `authTag` fields in addition to `ciphertext`. The format is now `{ ciphertext, iv, salt, authTag }` instead of a single hex string. Applications reading this encrypted data must be updated to parse all four fields.

**Decryption requirement**: Encrypted data now requires the salt and IV to be stored and retrieved with the ciphertext. The stored ciphertext from the old implementation cannot be decrypted with the new code without also storing the IV and salt separately. Applications must implement a dual-read path for legacy data or re-encrypt existing records.

**Authentication on every read**: Decryption now fails (throws `ERR_CRYPTO_INVALID_AUTH_TAG`) if the ciphertext or tag has been tampered with. This is not a breaking change for legitimate use, but monitoring systems should expect authentication failures for corrupted records instead of silent decryption of invalid data.
