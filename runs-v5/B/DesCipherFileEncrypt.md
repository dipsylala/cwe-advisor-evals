## Verdict

- **CWE-326** (Inadequate Encryption Strength)
- **Location**: `DesCipherFileEncrypt.go`, line 26 (`des.NewCipher(key)`)
- **Verdict**: exploitable
- **Confidence**: high

DES is a disallowed encryption algorithm under NIST SP 800-131A: its 56-bit effective key space (64-bit key with parity bits) has been within brute-force reach for decades, and NIST has retired even the stronger 3DES for new encryption use. There is no compensating control in this handler - the cipher is constructed directly from request input and used to encrypt the uploaded file with no fallback or additional protection.

## Source

- **Key material source**: `r.FormValue("key")` - attacker-controlled, taken directly from the HTTP request with no length or strength validation.
- **Protected data source**: `io.ReadAll(file)` - the uploaded file body, read from `r.FormFile("upload")`.
- **Sink**: `des.NewCipher(key)` (line 26), whose output block cipher feeds `cipher.NewCBCEncrypter(block, iv)` (line 33), which then encrypts the uploaded file via `mode.CryptBlocks(ciphertext, plaintext)` (line 35) and writes the result directly to the response.

The data flow is direct and unfiltered: request-supplied key bytes reach the weak-cipher constructor with no intermediate check, and the resulting ciphertext is returned to the client, so the encryption strength of the sink is the only protection the uploaded data receives in transit/at rest from this handler.

A second, related weakness sits alongside the flagged line: `iv := make([]byte, des.BlockSize)` is an all-zero, non-random IV reused for every request under CBC mode, which independently breaks semantic security regardless of the cipher choice. The fix below addresses both, since moving to an AEAD construction requires a properly generated nonce.

## Fix

No third-party library is required - the fix uses only the Go standard library (`crypto/aes`, `crypto/cipher`, `crypto/rand`, `crypto/sha256`), so there is no dependency version to track.

**Vulnerable code:**

```go
key := []byte(r.FormValue("key"))
// SAST FINDING: CWE-326 (Inadequate Encryption Strength) reported here. Sink is the next statement.
block, err := des.NewCipher(key)
if err != nil {
	http.Error(w, "invalid key", http.StatusBadRequest)
	return
}

iv := make([]byte, des.BlockSize)
mode := cipher.NewCBCEncrypter(block, iv)
ciphertext := make([]byte, len(plaintext))
mode.CryptBlocks(ciphertext, plaintext)

w.Write(ciphertext)
```

**Fixed code:**

```go
rawKey := []byte(r.FormValue("key"))
keyHash := sha256.Sum256(rawKey)
block, err := aes.NewCipher(keyHash[:])
if err != nil {
	http.Error(w, "invalid key", http.StatusBadRequest)
	return
}

gcm, err := cipher.NewGCM(block)
if err != nil {
	http.Error(w, "cipher init error", http.StatusInternalServerError)
	return
}

nonce := make([]byte, gcm.NonceSize())
if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
	http.Error(w, "nonce error", http.StatusInternalServerError)
	return
}

ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

w.Write(ciphertext)
```

(Full import block becomes `crypto/aes`, `crypto/cipher`, `crypto/rand`, `crypto/sha256`, `io`, `net/http` - `crypto/des` is removed.)

## Explanation

The fix replaces the DES/CBC construction with AES-256-GCM, an authenticated encryption (AEAD) mode, per the knowledge base's standard replacement for weak block-cipher primitives. `crypto/aes` with `cipher.NewGCM` requires a 16/24/32-byte key to select AES-128/192/256; since the request-supplied key string can be any length (as it was for DES, which itself required exactly 8 bytes), it is passed through `sha256.Sum256` to produce a fixed 32-byte key, selecting AES-256. The static, all-zero IV is eliminated by drawing a fresh nonce from `crypto/rand` on every call, sized from `gcm.NonceSize()` rather than a literal, and `gcm.Seal(nonce, nonce, plaintext, nil)` prefixes that nonce to the ciphertext as the documented pattern for later retrieval on decryption (`gcm.Open(nil, out[:gcm.NonceSize()], out[gcm.NonceSize():], nil)`). Together this closes both the inadequate-algorithm finding (DES to AES-256) and the reused-IV weakness that sat next to it, while keeping the resulting ciphertext self-contained (nonce + ciphertext+tag) so no additional wire format is needed.

## Behaviour changes

- **Ciphertext format changed**: the response body is now `nonce || ciphertext || 16-byte GCM tag` instead of raw CBC ciphertext. Any existing decryptor or stored ciphertext built against the old DES/CBC output is incompatible with the new format - this is a wire-format break, not just an internal change, and any consumer of this endpoint's output must be updated in lockstep. No dual-read path is provided because this handler produces ciphertext for immediate client consumption rather than persisting DES-encrypted records to migrate.
- **Key handling changed**: the raw form-supplied key bytes are no longer used directly as the cipher key; they are hashed with SHA-256 first. This is required because AES/GCM needs a 16/24/32-byte key while DES required exactly 8 bytes - without this step, arbitrary-length request input would fail `aes.NewCipher` for most inputs. This is a plain fixed-length transform, not a password KDF (no salt, no iteration count), since the original code gave no indication the "key" field is a low-entropy password rather than key material the caller already manages as a secret.
- **Plaintext length constraint removed**: the original `cipher.NewCBCEncrypter` + `CryptBlocks` path panics if the uploaded file's length is not a multiple of `des.BlockSize` (8 bytes), since no padding is applied before encryption. GCM is stream-based and has no block-alignment requirement, so this incidental crash-on-arbitrary-length-input bug is resolved as a side effect of the mode change, not as an intentional behavioural addition.
- Error-handling structure (status codes, early returns) is unchanged; the new `cipher.NewGCM` and nonce-generation steps add two new error branches that did not exist in the DES path, both returned as `500` since they represent internal cipher/RNG failures rather than caller-input problems, consistent with the existing style.

**Assumption**: the "key" form value is treated as opaque key material rather than a human-chosen password; if it is in fact operator/user-chosen and low-entropy, a password KDF such as `argon2.IDKey` (per the loaded Go guidance) should replace the plain `sha256.Sum256` sizing step, with the salt persisted alongside the ciphertext. This was resolved without asking per autonomous-mode rules; confidence on this specific point is medium, all other findings are high confidence.
