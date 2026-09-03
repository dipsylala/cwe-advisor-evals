## Verdict
Exploitable. The code uses DES (Data Encryption Standard) for encryption, which has only 56 effective bits of key strength and is cryptographically broken. DES is unsuitable for protecting sensitive data and must be replaced with a modern authenticated encryption algorithm.

## Source
User-supplied key from `r.FormValue("key")` at line 24, used directly in DES cipher initialization at line 26.

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

**Fixed code (replace imports and function body):**

Imports change from:
```go
import (
	"crypto/cipher"
	"crypto/des"
	"io"
	"net/http"
)
```

To:
```go
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net/http"
)
```

Function body (lines 24-37) changes to:
```go
key := []byte(r.FormValue("key"))
// Validate key length for AES-256
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
```

## Explanation
The fix replaces DES with AES-256-GCM, a modern authenticated encryption algorithm. AES-256 provides 256-bit security strength compared to DES's 56-bit strength. GCM (Galois/Counter Mode) provides authenticated encryption, preventing tampering and decryption of corrupted ciphertexts. The original static IV (initialized to zeros) is replaced with a cryptographically random nonce, which is prepended to the ciphertext by `gcm.Seal()`. The receiver splits the nonce from the ciphertext and passes it to `gcm.Open()` for authenticated decryption. Key length validation ensures AES-256's requirement for a 32-byte key is met before cipher initialization.

## Behaviour changes
- **Key length requirement**: Original code accepted any length key; fixed code requires exactly 32 bytes for AES-256, returning HTTP 400 if the key is incorrect length. This is a necessary security enforcement.
- **Nonce generation and transmission**: Original code used a static all-zeros IV that is not transmitted (receiver must use the same static IV). Fixed code generates a random 12-byte nonce per encryption and prepends it to the ciphertext. Receiver must extract the nonce before decryption. This prevents key/nonce reuse vulnerabilities.
- **Ciphertext format**: Original code outputs raw ciphertext only. Fixed code outputs nonce + ciphertext (gcm.Seal prefixes the nonce to dst). Receivers must split: first 12 bytes are nonce, remainder is ciphertext + authentication tag.
- **Authentication**: Original DES-CBC provides no authentication; GCM adds an authentication tag that is verified during decryption, rejecting tampered ciphertexts.
- **Error handling**: Added error check for `rand.Read()` to detect random number generation failures, and error check for `cipher.NewGCM()` creation.
- **Imported packages**: Replaced `crypto/des` with `crypto/aes` and added `crypto/rand`.
