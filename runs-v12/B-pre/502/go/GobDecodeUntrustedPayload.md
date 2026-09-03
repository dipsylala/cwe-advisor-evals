## Verdict

VULNERABLE. An attacker can send a malicious gob-encoded payload over HTTP to set privileged fields (`IsAdmin`, `Balance`) directly on the Account struct without server-side authorization checks.

## Source

Untrusted HTTP request body via `r.Body` in the `importAccountHandler` function.

## Fix

Replace `encoding/gob` deserialization with `encoding/json` and a purpose-built request DTO that contains only client-settable fields. Determine privileged fields (`IsAdmin`, `Balance`) from server-side authorization or defaults, not from the deserialized request.

**Fixed Code:**

```go
package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type Account struct {
	Username string
	Balance  int
	IsAdmin  bool
}

// Request DTO: only Username is client-settable.
type AccountRequest struct {
	Username string `json:"username"`
}

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	var req AccountRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Validate client-provided field.
	if len(req.Username) == 0 || len(req.Username) > 100 {
		http.Error(w, "invalid username", http.StatusBadRequest)
		return
	}

	// Construct Account with server-side authorization.
	// IsAdmin is determined by permission check, Balance by default or DB lookup.
	account := Account{
		Username: req.Username,
		Balance:  0, // Server-side default, not from request.
		IsAdmin:  checkAdminPermissions(r.Context()), // Server-side lookup.
	}

	saveAccount(account)
	w.WriteHeader(http.StatusOK)
}

func checkAdminPermissions(ctx context.Context) bool {
	// Determine admin status from session, JWT claims, or database lookup.
	// Never from client-provided data.
	return false // Placeholder: implement actual authorization.
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

The original code used `gob.NewDecoder()` on untrusted HTTP request data. Go's gob format instantiates and populates all exported struct fields without integrity checks or validation. An attacker can craft a malicious gob payload to set `IsAdmin: true` or manipulate `Balance` directly, bypassing any authorization logic.

The fix replaces gob with JSON and introduces a narrow request DTO (`AccountRequest`) containing only the `Username` field, which is the only value a client should provide. The `DisallowUnknownFields()` call rejects payloads with unexpected fields, hardening against mass-assignment variants. Privileged fields (`IsAdmin`, `Balance`) are now determined server-side: `IsAdmin` via a `checkAdminPermissions()` call based on session/JWT/database state, and `Balance` via a server-controlled default or database lookup. The Account struct is constructed explicitly from validated request fields plus server-computed authorization values, breaking the taint chain.

## Behaviour changes

- Request format changes from gob binary to JSON (clients must update serialization).
- Requests with unexpected JSON fields are now rejected with HTTP 400 (previously silently ignored).
- Username validation is enforced on the server (empty or >100 chars is rejected).
- IsAdmin and Balance are no longer client-controllable; they are now determined by server-side authorization logic and configuration.
- The endpoint is now safe against deserialization attacks; privilege escalation via malicious payloads is no longer possible.
