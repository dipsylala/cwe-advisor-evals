## Verdict

exploitable

## Source

`r.FormValue("key")` at line 24, user-controlled encryption key from form data.

## Fix

### File: DesCipherFileEncrypt.go

```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net/http"
)

func encryptUploadHandler(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("upload")
	if err != nil {
		http.Error(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	plaintext, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}

	key := []byte(r.FormValue("key"))
	block, err := aes.NewCipher(key)
	if err != nil {
		http.Error(w, "invalid key", http.StatusBadRequest)
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, "GCM initialization failed", http.StatusInternalServerError)
		return
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		http.Error(w, "random nonce generation failed", http.StatusInternalServerError)
		return
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	w.Write(ciphertext)
}
```

## Explanation

The original code uses DES encryption, which is cryptographically broken and has known practical attacks; it also uses CBC mode with a zero-initialized static IV, which is unauthenticated and reveals patterns in the plaintext. The fix replaces DES with AES-256 via `crypto/aes.NewCipher`, which meets modern security standards, and replaces CBC with GCM mode via `cipher.NewGCM`, which provides authenticated encryption (AEAD) that prevents both decryption of tampered ciphertexts and patterns leaking from identical plaintext blocks. A random nonce is generated from `crypto/rand` and prepended to the ciphertext output, following the Go idiom of storing the nonce alongside the ciphertext so decryption can extract and verify it. These changes together eliminate the weakness by removing the weak primitive and the unauthenticated mode, and by injecting randomness that prevents replay and pattern analysis.

## Behaviour changes

1. **Algorithm change (DES → AES-256)**: Stronger cryptographic primitive. AES requires a key of 16, 24, or 32 bytes; DES required 8 bytes or 16/24 for 3-key variants. Key validation error behavior changes accordingly, but remains defensive.

2. **Mode change (CBC → GCM)**: Unauthenticated CBC replaced with authenticated encryption (AEAD). CBC mode does not detect tampering; GCM will reject any modified ciphertext during decryption via `gcm.Open()`.

3. **IV/Nonce initialization (static zero → random)**: Original code used `make([]byte, des.BlockSize)` which zero-initializes the IV. The fix generates a random nonce via `crypto/rand.Read()`, preventing patterns in the ciphertext and supporting multiple encryptions under the same key.

4. **Nonce storage**: GCM nonce is prepended to the ciphertext via `gcm.Seal(nonce, nonce, plaintext, nil)`, which appends to the `dst` parameter. Decryption would extract the first `gcm.NonceSize()` bytes as the nonce before calling `gcm.Open()`. This is the standard Go pattern and matches the guidance.

5. **Additional error handling**: Added error check for `cipher.NewGCM()` and `rand.Read()`. These are defensive; the original code would have panicked or produced a nonce of zeros in these failure cases.

6. **Output format change**: Original code wrote just the ciphertext; the fix writes nonce + ciphertext concatenated. Any decryption logic must account for this by splitting at position `gcm.NonceSize()` before calling `gcm.Open()`.

