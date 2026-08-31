## Verdict

Exploitable. An attacker can craft a gob payload that sets `IsAdmin=true` or arbitrary `Balance` values on the `Account` struct during deserialization. The gob format instantiates and populates all struct fields directly from untrusted input with no integrity check, validation, or field restriction. These privileged fields are then saved without server-side authorization verification.

## Source

`r.Body` (HTTP request body) containing attacker-controlled gob-encoded data flows directly into `gob.NewDecoder(r.Body).Decode(&account)` on line 19.

## Fix

**Vulnerable code:**
```go
func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	var account Account

	// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
	if err := gob.NewDecoder(r.Body).Decode(&account); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	saveAccount(account)
	w.WriteHeader(http.StatusOK)
}
```

**Fixed code:**
```go
// Request DTO with only client-settable fields
type ImportAccountRequest struct {
	Username string `json:"username"`
}

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	var req ImportAccountRequest

	// Decode JSON with unknown-field rejection
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Validate request data
	if req.Username == "" || len(req.Username) > 100 {
		http.Error(w, "invalid username", http.StatusBadRequest)
		return
	}

	// Construct Account with server-controlled authorization and defaults
	account := Account{
		Username: req.Username,
		Balance:  0,          // Default; fetch from DB if needed
		IsAdmin:  false,      // Never from client; verify via server-side authorization
	}

	saveAccount(account)
	w.WriteHeader(http.StatusOK)
}
```

Also update the import section to use `encoding/json` instead of `encoding/gob`:
```go
import (
	"encoding/json"
	"log"
	"net/http"
)
```

## Explanation

The fix replaces `encoding/gob` deserialization with `encoding/json` and introduces a purpose-built request DTO (`ImportAccountRequest`) that contains only the `Username` field. The original code deserialized untrusted input directly into the domain `Account` struct, which includes sensitive fields (`IsAdmin`, `Balance`) that should never be settable by clients. By decoding into a narrower struct and explicitly constructing the `Account` object from validated request fields and server-controlled defaults, privileged fields cannot be manipulated by client payloads. The `DisallowUnknownFields()` call rejects any extra fields in the request, preventing field-injection attacks. Validation on the username ensures it meets length/format requirements. The server now owns the values for `Balance` and `IsAdmin`, which are either defaulted or fetched from server-side sources (database lookups or authorization checks), never from the deserialized request.

## Behaviour changes

- **Format change**: gob → json. Clients must send JSON instead of gob-encoded payloads. This is a breaking change for existing clients but is necessary for security and is the standard for HTTP APIs.
- **Field rejection**: The fixed code rejects payloads with unexpected fields (e.g., `IsAdmin` or `Balance`), whereas the original silently ignored them (gob would have accepted them). Clients that send extra fields now receive HTTP 400 instead of success.
- **Validation added**: Username is validated for empty or excessive length (>100 chars). Requests with invalid usernames now return HTTP 400 instead of being saved with truncated/empty data.
- **Default initialization**: `Balance` is now hardcoded to 0 and `IsAdmin` to false; if these should be fetched from a database or computed from server-side state, add a DB lookup in place of the hardcoded default (no change to the security fix itself, only the business logic).
- **Response unchanged**: HTTP 200 on success, 400 on parsing/validation errors. The overall contract is preserved.
