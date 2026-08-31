## Verdict

The finding is valid. Line 26 uses `crypto/des.NewCipher()`, which implements DES - cryptographically broken and disallowed for encryption. Additionally, the code uses CBC mode with a zero IV (line 32) and no authentication, creating predictable ciphertexts and exposing the data to padding oracle attacks.

## Source

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

## Fix

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

	// Derive a 32-byte key from the form value
	keyInput := r.FormValue("key")
	keyHash := sha256.Sum256([]byte(keyInput))
	key := keyHash[:]

	// Use AES-256 instead of DES
	block, err := aes.NewCipher(key)
	if err != nil {
		http.Error(w, "invalid key", http.StatusBadRequest)
		return
	}

	// Use GCM mode for authenticated encryption
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, "cipher error", http.StatusInternalServerError)
		return
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, "nonce error", http.StatusInternalServerError)
		return
	}

	// Seal the plaintext with authenticated encryption
	// Seal appends to dst, so we prepend the nonce to the output
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	w.Write(ciphertext)
}
```

## Explanation

The fix replaces DES+CBC with AES-256-GCM. This eliminates the weakness in three ways:

1. **Adequate key strength**: AES-256 provides 256-bit security strength (well above the 2031 sunset threshold for weaker primitives). The form value is hashed via SHA-256 to derive a proper 32-byte key.

2. **Authenticated encryption**: GCM mode combines encryption and authentication in a single primitive, preventing padding oracle attacks and detecting ciphertext tampering. The MAC is verified during decryption.

3. **Non-predictable nonce**: A cryptographically random nonce is generated for each encryption via `crypto/rand.Read()`, ensuring identical plaintexts produce different ciphertexts and preventing replay attacks. The nonce is prepended to the ciphertext so the recipient can extract it during decryption.

The decryption side must split the ciphertext to extract the nonce before calling `gcm.Open(nil, out[:gcm.NonceSize()], out[gcm.NonceSize():], nil)`.

## Behaviour changes

- **Encryption output changes**: Ciphertext format now includes a prepended random nonce (not encrypted). Each encryption produces a different ciphertext for the same plaintext due to the random nonce.
- **Authentication now enforced**: Decryption will fail if the ciphertext is tampered with. Any modification to the ciphertext or nonce will cause `gcm.Open()` to return an error.
- **Key derivation added**: The form's key value is now hashed to a fixed 32-byte length rather than used directly. This prevents errors from non-standard key lengths and provides consistent key strength.
- **Error handling expanded**: Two new error checks added for `NewGCM()` and `rand.Read()`. These should be rare in production but are necessary to handle the cipher initialization and nonce generation.
