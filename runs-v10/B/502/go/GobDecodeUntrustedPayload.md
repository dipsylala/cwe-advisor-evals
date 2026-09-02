## Verdict

Real vulnerability confirmed. The code deserializes untrusted HTTP request body data using `encoding/gob` directly into a struct containing privileged fields (`IsAdmin`), allowing attackers to forge admin status.

## Source

`r.Body` from the HTTP request handler - attacker-controlled data.

## Fix

Replace `encoding/gob` deserialization with `encoding/json` and a request DTO containing only client-settable fields. Determine privileged fields (`IsAdmin`) from server-side authorization, not from the request:

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

// Request DTO: contains only client-settable fields
type AccountRequest struct {
	Username string `json:"username"`
}

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	var req AccountRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // Reject unexpected fields
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Validate client-supplied field
	if req.Username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	// Construct the domain object explicitly, deriving privileged fields from server-side authorization
	account := Account{
		Username: req.Username,
		Balance:  0, // Server-determined default
		IsAdmin:  false, // Privileged field: never from request
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

The vulnerability arose because `encoding/gob` will instantiate and populate any registered struct field from untrusted input without integrity checks. The privileged field `IsAdmin` was directly settable by an attacker's crafted gob payload.

The fix replaces `gob` with `encoding/json` and a request DTO (`AccountRequest`) containing only fields the client should control (`Username`). `DisallowUnknownFields()` rejects payloads with unexpected fields, preventing field injection. Privileged fields (`IsAdmin`, `Balance`) are now server-determined and never copied from the request struct, eliminating the vector for privilege escalation.

## Behaviour changes

- **Input format:** The endpoint now accepts JSON instead of gob binary format. Callers must send `Content-Type: application/json` with JSON payloads.
- **Field rejection:** Requests with extra fields (e.g. `{"username":"alice","isAdmin":true}`) are now rejected with HTTP 400 instead of silently ignoring unknown fields.
- **Validation:** The handler now validates that `Username` is not empty. Empty usernames are rejected.
- **Privilege model:** `IsAdmin` is now always `false` for imported accounts and must be set through a separate, authorized administrative API. Previously, an attacker could forge this field in the gob payload.
- **Balance handling:** `Balance` now defaults to 0 on import rather than being deserializable. Balance changes should be routed through a separate, authorized transaction API.
