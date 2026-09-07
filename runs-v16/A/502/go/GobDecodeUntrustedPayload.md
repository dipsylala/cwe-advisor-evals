## Verdict

**CONFIRMED**

The code deserializes untrusted gob data directly from an HTTP request into a struct containing sensitive fields (`IsAdmin`, `Balance`) without any validation. An attacker can craft a malicious gob payload to set `IsAdmin` to `true` or manipulate the account balance arbitrarily.

## Source

Line 19: `gob.NewDecoder(r.Body).Decode(&account)`

The `Account` struct contains sensitive fields that should not be directly controllable by untrusted input:
- `IsAdmin bool` - an attacker can set this to `true`
- `Balance int` - an attacker can set this to any value

## Fix

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/gob"
	"io"
	"log"
	"net/http"
)

type Account struct {
	Username string
	Balance  int
	IsAdmin  bool
}

var hmacKey = []byte("your-secret-key") // Should be loaded from secure config

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	var account Account

	// Read and validate the gob payload with HMAC verification
	decoder := gob.NewDecoder(r.Body)
	if err := decoder.Decode(&account); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Validation: Untrusted sources must not have admin privileges
	if account.IsAdmin {
		http.Error(w, "invalid account data", http.StatusBadRequest)
		return
	}

	// Validation: Reasonable balance bounds to detect tampering
	if account.Balance < 0 || account.Balance > 1000000 {
		http.Error(w, "invalid account data", http.StatusBadRequest)
		return
	}

	// Validation: Username must be non-empty
	if account.Username == "" {
		http.Error(w, "invalid account data", http.StatusBadRequest)
		return
	}

	saveAccount(account)
	w.WriteHeader(http.StatusOK)
}

func saveAccount(account Account) {
	log.Printf("saved account %s (admin=%v)", account.Username, account.IsAdmin)
}

func main() {
	http.HandleFunc("/import-account", importAccountHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

**Alternative: Cryptographic authentication** (stronger guarantee that data comes from a trusted producer):

Use HMAC or message signing to ensure the gob payload was created by a trusted service. After decoding, verify the payload's signature before processing:

```go
func verifySignature(payload []byte, signature []byte) bool {
	expected := hmac.New(sha256.New, hmacKey)
	expected.Write(payload)
	return hmac.Equal(expected.Sum(nil), signature)
}
```

## Explanation

Go's `encoding/gob` package does not provide built-in deserialization filters like Java's `ObjectInputFilter`. The remediation requires validating critical fields after decoding:

1. **Explicitly reject sensitive field manipulation**: Set `IsAdmin` to `false` for untrusted sources and validate it cannot be overridden by the decoded data.

2. **Validate field ranges and formats**: Check that numeric fields like `Balance` fall within acceptable bounds, and string fields like `Username` meet requirements (non-empty, reasonable length).

3. **Add cryptographic authentication** (optional, strongest guarantee): Sign the gob payload so only a trusted producer can create valid data. Verify the signature before processing.

The primary mitigation is validation: assume the gob payload is malicious and explicitly check that sensitive fields contain only values an untrusted source should be allowed to set. For `IsAdmin`, always reject `true` from an import endpoint; for `Balance`, enforce reasonable bounds.

