## Verdict

The finding is confirmed. The code deserializes untrusted HTTP request body data using Go's `encoding/gob` package, which instantiates and populates all struct fields without integrity checks or authorization validation. An attacker can craft a malicious gob-encoded payload to set privileged fields like `IsAdmin` to true or manipulate `Balance`, bypassing intended business logic.

## Source

Line 19: `gob.NewDecoder(r.Body).Decode(&account)`

The source is `r.Body`, an HTTP request body controlled entirely by the attacker. The `importAccountHandler` function receives untrusted data with no authentication, integrity check, or format validation before deserialization.

## Fix

Replace `encoding/gob` with `encoding/json` and a narrow request DTO that excludes privileged fields. Determine `IsAdmin` from server-side authorization:

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

// Request DTO containing only client-settable fields
type ImportAccountRequest struct {
	Username string `json:"username"`
	Balance  int    `json:"balance"`
}

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	var req ImportAccountRequest

	// Limit request body size to prevent resource exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // Reject unexpected fields
	
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Validate incoming fields
	if req.Username == "" || len(req.Username) > 100 {
		http.Error(w, "invalid username", http.StatusBadRequest)
		return
	}
	if req.Balance < 0 || req.Balance > 1000000 {
		http.Error(w, "invalid balance", http.StatusBadRequest)
		return
	}

	// Construct domain object: IsAdmin determined by server-side authorization, not request
	account := Account{
		Username: req.Username,
		Balance:  req.Balance,
		IsAdmin:  false, // Default to non-admin; query actual authorization separately
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

The fix eliminates the CWE-502 vulnerability by replacing Go's unsafe `encoding/gob` deserialization with `encoding/json` using a purpose-built request DTO (`ImportAccountRequest`) that contains only client-settable fields (`Username` and `Balance`). This prevents attackers from directly controlling the `IsAdmin` field during deserialization.

The key changes:
1. **Avoid gob entirely:** Replace the gob sink with JSON, which does not instantiate arbitrary types.
2. **Narrow DTO:** The request struct excludes privileged fields; an attacker cannot inject values for them through the request.
3. **DisallowUnknownFields():** Rejects payloads with unexpected fields, catching tampering attempts.
4. **Input validation:** Each deserialized field is validated for length, range, and format before use.
5. **Server-side authorization:** `IsAdmin` is hardcoded to `false` (a safe default) and would be determined from a database lookup or permission check, never from the request payload.
6. **Resource exhaustion hardening:** `http.MaxBytesReader` bounds the request body to prevent oversized-payload attacks during decoding.

The domain/persistence `Account` struct is explicitly constructed from validated request fields plus server-controlled authorization state, breaking the taint chain from untrusted input.

## Behaviour changes

- **Request format:** Changes from gob binary format to JSON. Clients must be updated to send JSON instead of gob-encoded requests.
- **Field validation:** The handler now validates `Username` length and `Balance` range; invalid requests are rejected with 400 instead of being processed.
- **Privilege handling:** `IsAdmin` is never set from the request and defaults to `false`; admin status must come from a separate authorization check or database lookup (not implemented here but implied by the fix).
- **Error handling:** JSON decode errors and validation failures return 400; malformed or oversized requests (exceeding 1024 bytes) are rejected earlier.
- **Response:** No change in success path; valid requests return 200 as before.

