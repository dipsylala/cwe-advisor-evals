## Verdict
exploitable

## Source
User-supplied encryption key via `r.FormValue("key")` at line 24; user-uploaded file content at line 18.

## Fix

**Vulnerable code (lines 24-37):**
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
key := []byte(r.FormValue("key"))
// Ensure key is 32 bytes for AES-256
if len(key) != 32 {
    http.Error(w, "key must be 32 bytes", http.StatusBadRequest)
    return
}

block, err := aes.NewCipher(key)
if err != nil {
    http.Error(w, "invalid key", http.StatusBadRequest)
    return
}

gcm, err := cipher.NewGCM(block)
if err != nil {
    http.Error(w, "cipher error", http.StatusInternalServerError)
    return
}

nonce := make([]byte, gcm.NonceSize())
if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
    http.Error(w, "random error", http.StatusInternalServerError)
    return
}

ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
w.Write(ciphertext)
```

## Explanation
DES is cryptographically broken—NIST disallowed it for encryption after December 31, 2023. Additionally, CBC mode with a zero-initialized IV allows attackers to detect repeated plaintexts across requests and potentially recover plaintext through padding oracle attacks. The fix replaces DES with AES-256 (128-bit security strength) and switches to AES-GCM, which provides both confidentiality and authentication. The nonce is generated randomly from `crypto/rand` and prepended to the ciphertext so the receiver can split and extract it for decryption. AES-GCM prevents padding oracle attacks and detects tampering—if the ciphertext is modified, `GCM.Open` will fail.

## Behaviour changes

- **Key length validation added:** The code now validates that the supplied key is exactly 32 bytes (AES-256 requirement). A key of any other length is rejected with a 400 error. This is a breaking change for clients supplying 8-byte DES keys, but required for secure cryptography.
- **Nonce prepended to ciphertext:** The fixed code prefixes the random nonce to the ciphertext (`gcm.Seal(nonce, ...)`), increasing output size by 12 bytes and requiring the receiver to extract the nonce before decryption. This is necessary for each encryption to be unique and for the receiver to recover the nonce without a separate channel.
- **Authentication now enforced:** AES-GCM automatically authenticates the ciphertext; any tampering will cause decryption to fail. The original CBC mode provided no authentication.
- **Requires crypto/rand import:** The fixed code imports `crypto/rand` for secure random nonce generation. The original code had no randomness dependencies.
- **Requires crypto/aes import:** Must import `crypto/aes` in place of `crypto/des`.
