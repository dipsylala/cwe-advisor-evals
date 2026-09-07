## Verdict

Exploitable. The code uses DES encryption, a cryptographically broken algorithm, combined with CBC mode and a static zero-filled IV, making the ciphertext vulnerable to padding oracle attacks and ensuring no authentication.

## Source

User-supplied key from `r.FormValue("key")` at line 24, passed unsanitized to the DES cipher.

## Fix

**Vulnerable code:**
```go
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
	// VULNERABLE: DES is cryptographically broken
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
}
```

**Fixed code:**
```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
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

	// Derive a 32-byte key from the user-supplied key using SHA-256
	keyHash := sha256.Sum256([]byte(r.FormValue("key")))
	key := keyHash[:]

	// Use AES-GCM for authenticated encryption
	block, err := aes.NewCipher(key)
	if err != nil {
		http.Error(w, "invalid key", http.StatusInternalServerError)
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, "gcm error", http.StatusInternalServerError)
		return
	}

	// Generate a random nonce for each encryption
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, "random error", http.StatusInternalServerError)
		return
	}

	// Encrypt with GCM; Seal appends to dst, so dst is the nonce slice
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	w.Write(ciphertext)
}
```

## Explanation

The fix replaces DES (cryptographically broken) with AES-256-GCM, which provides both confidentiality and authentication. AES-GCM is an authenticated encryption with associated data (AEAD) cipher that prevents both decryption of altered ciphertexts and padding oracle attacks.

The user-supplied key is derived using SHA-256 to produce a proper 32-byte key for AES-256. A cryptographically random nonce is generated for each encryption and prepended to the ciphertext by `gcm.Seal()`, so the receiver can extract it and decrypt without a separate transmission channel.

The fix eliminates three weaknesses: the broken DES algorithm, the static IV (replaced with a random nonce), and the lack of authentication (GCM provides authenticated encryption).

## Behaviour changes

1. **Import changes**: Added `crypto/aes`, `crypto/rand`, and `crypto/sha256` imports; removed `crypto/des` dependency.
2. **Key derivation**: User-supplied key is now hashed with SHA-256 to produce a proper 32-byte key, rather than used directly. This ensures consistent key length and entropy.
3. **Nonce generation**: A random nonce is generated for each encryption and prepended to the ciphertext (handled by `gcm.Seal(nonce, ...)`). Decryption requires extracting the first `gcm.NonceSize()` bytes before calling `gcm.Open()`.
4. **Ciphertext format change**: The output format changes from raw ciphertext to `nonce || ciphertext`. This is a breaking change for existing encrypted data; a migration path must either re-encrypt all stored data or implement a dual-read that tries GCM first, then falls back to DES for legacy data.
5. **Authentication**: GCM automatically authenticates the ciphertext; a tampered message will fail decryption with `cipher.ErrOpen` equivalent.
6. **Error handling**: Added error handling for `cipher.NewGCM()` and `rand.Read()` to surface failures early.

