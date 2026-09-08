## Verdict

CWE-326 confirmed. DES encryption with CBC mode and no message authentication provides inadequate encryption strength and is vulnerable to padding oracle attacks.

## Source

Line 24: User-supplied key from HTTP form value (`r.FormValue("key")`).
Line 18: Plaintext from uploaded file (`io.ReadAll(file)`).

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

	keyStr := r.FormValue("key")
	if len(keyStr) != 32 {
		http.Error(w, "key must be 32 bytes", http.StatusBadRequest)
		return
	}
	key := []byte(keyStr)

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
	_, err = rand.Read(nonce)
	if err != nil {
		http.Error(w, "random error", http.StatusInternalServerError)
		return
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	w.Write(ciphertext)
}
```

## Explanation

The fix replaces DES with AES-256 and CBC mode with GCM (Galois/Counter Mode), which provides authenticated encryption. AES-256 meets NIST strength requirements indefinitely. GCM provides both confidentiality and authenticity, eliminating the padding oracle vulnerability present in CBC without a MAC.

A random nonce is generated and prepended to the ciphertext using `gcm.Seal(nonce, nonce, plaintext, nil)` where `nonce` is both the destination slice (causing it to be prefixed) and the nonce argument. Decryption splits the prefix back as `gcm.Open(nil, out[:gcm.NonceSize()], out[gcm.NonceSize():], nil)`. The key is validated to be exactly 32 bytes for AES-256. Additional authenticated data (the fourth argument to `Seal` and `Open`) is set to `nil` as none is required here.

## Behaviour changes

- Ciphertext format changes: previously pure CBC output, now a random nonce is prepended to the authenticated ciphertext
- Key size requirement enforced: must be exactly 32 bytes (256 bits) instead of variable DES key sizes
- Authentication is now provided: ciphertext tampered in transit will be rejected during decryption
- Each encryption produces different ciphertext even for identical plaintexts (due to random nonce)
- Decryption of old DES-encrypted records will fail; a migration path reading legacy ciphertext through the old DES code before re-encrypting under AES is required if old records exist
