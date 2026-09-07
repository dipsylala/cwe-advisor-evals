## Verdict

Exploitable. User-supplied passphrase flows to `crypto.createCipher()`, which uses an insecure key derivation function, no initialization vector, and lacks authenticated encryption. The vulnerability permits decryption oracles and key recovery attacks.

## Source

`req.body.passphrase` (line 8): HTTP request body parameter supplied by client.

## Fix

**Vulnerable code (line 16):**
```javascript
const cipher = crypto.createCipher('aes-256-cbc', passphrase);
```

**Fixed code (lines 16-20):**
```javascript
const salt = crypto.randomBytes(32);
const key = crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
```

**Additional required change (after line 19):**

The response must capture and store the authentication tag and salt so decryption can verify them. Replace:
```javascript
res.json({ ciphertext: encrypted });
```

With:
```javascript
const authTag = cipher.getAuthTag();
const result = {
  salt: salt.toString('hex'),
  iv: iv.toString('hex'),
  ciphertext: encrypted,
  authTag: authTag.toString('hex')
};
res.json({ ciphertext: result });
```

## Explanation

The fix replaces the deprecated `crypto.createCipher` with `crypto.createCipheriv` using AES-256-GCM, which provides both confidentiality and authenticated encryption. The passphrase is now properly derived to a 32-byte key using PBKDF2-SHA256 (100,000 iterations per OWASP guidance) with a random salt. A fresh 12-byte IV is generated for each encryption. The authentication tag is extracted after finalizing the cipher and stored alongside the salt, IV, and ciphertext so that decryption can verify the tag with `decipher.setAuthTag()` before calling `decipher.final()`, ensuring no tampered ciphertexts are accepted. This eliminates the weak key derivation, implicit-zero IV, and padding oracle exposure of CBC mode.

## Behaviour changes

1. **Response format changed:** The endpoint now returns a JSON object with `salt`, `iv`, `ciphertext`, and `authTag` fields (all hex-encoded) instead of a simple ciphertext string. Any client expecting the previous format will require an update to parse the new structure.

2. **Key derivation now explicit:** PBKDF2 with a random salt replaces the deprecated EVP_BytesToKey algorithm. This makes the key derivation visible and auditable. The salt must be stored and used during decryption to reconstruct the same key.

3. **IV is now explicit:** Each encryption generates a fresh random 12-byte IV. The IV must be stored and used during decryption; it is not secret but must be transmitted with the ciphertext.

4. **Authentication tag verification required:** Decryption must now extract the stored auth tag and call `decipher.setAuthTag(authTag)` before `decipher.final()`, which will throw if any part of the ciphertext, IV, or tag has been modified. Existing ciphertexts encrypted under the old algorithm cannot be decrypted with this code and will require either a legacy decryption path or re-encryption.

5. **Slightly increased ciphertext size:** The response now includes salt (32 bytes hex = 64 chars), IV (12 bytes hex = 24 chars), and tag (16 bytes hex = 32 chars) alongside the ciphertext, increasing payload by ~120 characters per message. This is a necessary trade-off for authenticated encryption.
