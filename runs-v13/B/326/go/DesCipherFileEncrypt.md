## Verdict

Exploitable. DES is cryptographically broken and disallowed for any encryption use. The code uses DES to encrypt user-supplied file data in CBC mode with a static zero-initialized IV, creating multiple weaknesses: inadequate encryption strength from DES itself, lack of authentication enabling tampering, and a padding oracle attack surface from unverified CBC decryption.

## Source

Line 24: `key := []byte(r.FormValue("key"))` — user-supplied key from HTTP form parameter, passed directly to the encryption sink without length validation.

## Sink

Line 26: `block, err := des.NewCipher(key)` — DES cipher initialization, followed by CBC encryption (lines 32–35) with a zero-initialized nonce.

## Fix

**Vulnerable code:**
```go
package main

import (
	"crypto/cipher"
	"crypto/des"
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
}
```

**Fixed code:**
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
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, "random error", http.StatusInternalServerError)
		return
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	w.Write(ciphertext)
}
```

## Explanation

DES (Data Encryption Standard) is cryptographically broken and provides only 56 bits of effective key strength, making it vulnerable to brute-force attacks. The original code also compounds this by using CBC mode without authentication or integrity verification, which enables padding oracle attacks and allows undetected tampering with the ciphertext.

The fix replaces DES with AES-256 (a 256-bit key requires 32 bytes), which provides 256 bits of security strength. It replaces the unauthenticated CBC mode with AES-GCM, an authenticated encryption with associated data (AEAD) cipher that both encrypts the data and verifies its integrity. A cryptographically random nonce is generated for each encryption and prepended to the ciphertext using `gcm.Seal(nonce, nonce, plaintext, nil)`, as documented in the Go crypto guidance. This construction ensures that identical plaintexts produce different ciphertexts and that any tampering with the ciphertext is detected during decryption. The decryption path must extract the nonce from the received ciphertext before calling `gcm.Open(nil, out[:gcm.NonceSize()], out[gcm.NonceSize():], nil)`.

## Behaviour changes

- **Algorithm swap (DES to AES-256)**: Eliminates the inadequate encryption strength weakness by moving from 56 bits to 256 bits of security. This is the core fix.
- **Mode swap (CBC to GCM)**: Eliminates the lack of authentication and padding oracle attack surface by switching from an unauthenticated stream cipher mode to AEAD. GCM requires that the ciphertext be verified before decryption.
- **Nonce generation**: A cryptographically random nonce is now generated for each encryption and prepended to the ciphertext via `gcm.Seal(nonce, nonce, plaintext, nil)`. This is required for AEAD security; reusing a nonce under the same key breaks GCM security.
- **Key length validation**: AES requires keys of exactly 16, 24, or 32 bytes. The fix enforces a 32-byte key requirement and rejects shorter or longer keys with an HTTP 400 error. This prevents silent truncation or padding.
- **Import changes**: `crypto/des` is removed and replaced with `crypto/aes` and `crypto/rand`. The `cipher.NewGCMWithRandomNonce` function is not used here (requires Go 1.24); instead, the random nonce is generated explicitly.
- **Error handling**: Additional error checks are added for `cipher.NewGCM`, key length validation, and random nonce generation. These errors are reported as HTTP 500 (internal server error) rather than 400 to preserve the distinction between client input validation errors and server-side cryptographic failures.
- **Ciphertext format**: The output format changes from bare ciphertext to `nonce || ciphertext` (nonce prepended). Decryption code must be updated to extract the nonce before calling `gcm.Open()`.
