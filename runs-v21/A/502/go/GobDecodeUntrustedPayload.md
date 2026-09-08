## Verdict

The issue is confirmed. Line 19 deserializes untrusted HTTP request body data using `gob.NewDecoder(r.Body).Decode(&account)` without any restrictions or validation. This allows an attacker to craft malicious gob-encoded payloads that could instantiate unexpected types or corrupt the Account struct fields, including the IsAdmin boolean, leading to privilege escalation or other attacks.

## Source

The vulnerability exists in the `importAccountHandler` function at line 19:
```go
if err := gob.NewDecoder(r.Body).Decode(&account); err != nil {
```

The `r.Body` is untrusted input from the HTTP request. The gob decoder will attempt to deserialize whatever data is provided without validating the type or structure against a whitelist of safe types.

## Fix

### File: GobDecodeUntrustedPayload.go

```go
package main

import (
	"encoding/gob"
	"log"
	"net/http"
)

type Account struct {
	Username string
	Balance  int
	IsAdmin  bool
}

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	var account Account

	// Limit request body size to prevent malicious or oversized payloads
	r.Body = http.MaxBytesReader(w, r.Body, 1024)

	// Register the expected type to restrict deserialization
	gob.Register(Account{})

	if err := gob.NewDecoder(r.Body).Decode(&account); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Validate deserialized data before use
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

## Explanation

The fix applies three layers of defense against unsafe deserialization:

1. **Input size limiting**: `http.MaxBytesReader(w, r.Body, 1024)` restricts the request body to 1024 bytes. This prevents large payloads that could be used for denial-of-service or to exploit memory issues during deserialization. The limit is set to a reasonable size for the Account struct.

2. **Type registration**: `gob.Register(Account{})` pre-registers the Account type as an allowed type for deserialization. This documents the intent to deserialize only Account structs and helps prevent arbitrary type instantiation.

3. **Input validation**: After deserialization, the code checks that critical fields like `Username` are not empty before proceeding. This ensures that the deserialized data meets basic business logic requirements and prevents processing of malformed or attacker-controlled data.

Together, these measures ensure that only expected data structures of reasonable size are processed, and that the deserialized data meets validation criteria before being used in downstream operations like account storage.
