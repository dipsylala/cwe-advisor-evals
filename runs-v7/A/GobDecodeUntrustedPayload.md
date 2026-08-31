## Verdict
Confirmed. The handler deserializes untrusted gob-encoded data directly from the HTTP request body without any integrity verification, enabling arbitrary object instantiation and potential code execution via crafted serialized payloads.

## Source
Line 19: `gob.NewDecoder(r.Body).Decode(&account)`

The `Account` struct deserialization accepts a request body from any client without validation of authenticity or integrity.

## Fix
Replace gob deserialization with JSON and add HMAC-based authentication:

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

type Account struct {
	Username string `json:"username"`
	Balance  int    `json:"balance"`
	IsAdmin  bool   `json:"is_admin"`
}

type SignedPayload struct {
	Data      Account `json:"data"`
	Signature string  `json:"signature"`
}

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	var payload SignedPayload

	// Parse JSON instead of gob
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Verify HMAC signature using a shared secret
	secret := os.Getenv("PAYLOAD_SECRET")
	if secret == "" {
		http.Error(w, "server configuration error", http.StatusInternalServerError)
		return
	}

	// Reconstruct and verify the signature
	expectedSig := computeSignature(payload.Data, secret)
	if !hmac.Equal([]byte(payload.Signature), []byte(expectedSig)) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	saveAccount(payload.Data)
	w.WriteHeader(http.StatusOK)
}

func computeSignature(account Account, secret string) string {
	// Serialize the account data deterministically
	data, _ := json.Marshal(account)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func saveAccount(account Account) {
	log.Printf("saved account %s (admin=%v)", account.Username, account.IsAdmin)
}

func main() {
	http.HandleFunc("/import-account", importAccountHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## Explanation
Gob encoding is unsafe for untrusted data because it directly instantiates Go objects during deserialization without cryptographic verification. Attackers can craft malicious serialized payloads to invoke arbitrary methods or modify object fields.

The fix introduces two critical controls:

1. **Format change to JSON**: Replaces gob with JSON, which parses as inert data structures and does not instantiate arbitrary types during unmarshaling. JSON's surface is limited to scalars and maps—no method invocation.

2. **HMAC-SHA256 authentication**: Requires the client to include a cryptographic signature computed over the account data using a shared secret. The server recomputes the signature and compares it using constant-time comparison (`hmac.Equal`) to prevent timing attacks. Only requests with a valid signature are processed.

The shared secret should be stored securely (e.g., in environment variables or a secrets manager) and never hardcoded. This pattern ensures that even if the payload format is observed, an attacker cannot forge valid requests without knowing the secret.
