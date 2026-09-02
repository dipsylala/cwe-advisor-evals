## Verdict

**exploitable** (confidence: high)

- cwe_id: CWE-326 (Inadequate Encryption Strength)
- location: `DesCipherFileEncrypt.go`, line 26 (`des.NewCipher(key)`)

`crypto/des` implements single DES, a 56-bit effective key length that is brute-forceable with commodity hardware, and the finding's block cipher is then driven through `cipher.NewCBCEncrypter` with a fixed, all-zero IV (`make([]byte, des.BlockSize)`, never randomized) and no message authentication. Both the algorithm choice and the construction around it are broken; nothing before line 26 constrains or validates the key in a way that removes the exposure.

## Source

- **Source**: `r.FormValue("key")` (line 24) — an attacker-controlled value taken directly from the multipart HTTP request; `plaintext` (line 18, from `r.FormFile("upload")`) is the attacker-controlled data being protected.
- **Sink**: `des.NewCipher(key)` (line 26), whose output `block` feeds `cipher.NewCBCEncrypter(block, iv)` (line 33) with the static zero IV, and `mode.CryptBlocks` (line 35) writes the ciphertext returned directly to the HTTP response (line 37).
- No intermediate check narrows the key's length, source, or entropy, and no MAC is computed over the ciphertext — the full weak-cipher-plus-weak-mode path is reachable on every request that includes an 8-byte `key` form value.

## Fix

No third-party library is needed; the fix uses only the Go standard library (`crypto/aes`, `crypto/cipher`, `crypto/rand`, `crypto/sha256`), so no manifest change or version floor applies.

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
keyBytes := sha256.Sum256([]byte(r.FormValue("key")))
block, err := aes.NewCipher(keyBytes[:])
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

(Imports change from `"crypto/cipher"`, `"crypto/des"` to `"crypto/aes"`, `"crypto/cipher"`, `"crypto/rand"`, `"crypto/sha256"`, keeping `"io"` and `"net/http"`.)

## Explanation

The fix replaces single-DES-CBC with AES-256-GCM, an authenticated encryption (AEAD) construction, per the CWE-326 Go guidance's remediation step to swap DES/CBC for `cipher.NewGCM(block)` over an AES-256 key. The user-supplied `key` form value is hashed with `sha256.Sum256` to produce a fixed 32-byte AES-256 key, since `aes.NewCipher` requires a 16/24/32-byte key and the original raw bytes cannot be assumed to already be that length; this hash step is a length-normalizer for raw key material, not a password KDF, matching the original code's treatment of the field as a directly-supplied key rather than a low-entropy password. The static all-zero IV is removed and replaced with a fresh random nonce read from `crypto/rand` for every request, sized from `gcm.NonceSize()` rather than a literal, and `gcm.Seal(nonce, nonce, plaintext, nil)` prefixes that nonce onto the returned ciphertext (per the guidance's documented `Seal` behavior) so the recipient can recover it for decryption. Together this closes both the weak-algorithm finding (DES's 56-bit key) and the weak-mode issue the same sink exposed (a static IV in CBC with no integrity check), replacing it with a construction that is both strong and tamper-evident.

## Behaviour changes

- **Key-size validation now unreachable as originally written**: the original `invalid key` 400 response was reachable whenever the submitted `key` form value was not exactly 8 bytes (DES's fixed key size). After hashing with SHA-256, the derived key is always exactly 32 bytes, so `aes.NewCipher` never returns an error and that branch becomes dead code for this call site. This is a necessary consequence of normalizing arbitrary-length input into a valid AES-256 key; it is not disguised as still enforcing a length check, and no request that previously succeeded is now rejected on account of key length.
- **Any-length key now accepted**: previously only an exactly-8-byte `key` value produced a working cipher; now any non-empty string produces a valid 32-byte AES key via hashing. This is required to use a stronger cipher while preserving the field's "raw key from the client" contract without adding a separate key-provisioning step.
- **Response body format changes**: the ciphertext written to `w` now has a 12-byte random nonce prepended and a 16-byte GCM authentication tag appended, so `len(response) == len(plaintext) + 28` instead of `len(response) == len(plaintext)` (rounded to the DES block size) as before. Any client decrypting this response must be updated to split the nonce (first `gcm.NonceSize()` bytes) before calling `gcm.Open` with the remainder, and must reject the response if authentication fails — this is inherent to moving from unauthenticated CBC to an AEAD mode and is required to close the weakness, not incidental.
- **Ciphertext is no longer deterministic**: with the original static all-zero IV, encrypting the same plaintext under the same key always produced the same ciphertext; with a random nonce per call, it now does not. This is intentional — a static IV was itself part of the reported weakness (pattern leakage across requests) — but is called out because callers relying on deterministic output (e.g. for caching or comparison) will observe different behavior.
- **No other logic, status codes, error handling structure, or control flow changed.** File-read handling (lines 10-22) and the HTTP error paths for missing file / read error are untouched.
