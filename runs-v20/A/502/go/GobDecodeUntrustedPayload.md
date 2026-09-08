## Verdict

Confirmed. `importAccountHandler` runs `gob.NewDecoder(r.Body).Decode(&account)` directly against the raw HTTP request body. Go's `encoding/gob` format has no schema or authorization boundary of its own: whatever bytes the client sends are unmarshalled straight into every exported field of `Account`, including `IsAdmin`. An attacker can post a hand-crafted gob stream that sets `IsAdmin: true` for any username, and `saveAccount` will persist it as-is. This is a deserialization-of-untrusted-data issue that manifests as a privilege-escalation vector: the wire format hands the client direct control over a security-relevant field that should only ever be set by server-side logic. `gob` is also documented as intended for trusted peers exchanging data with matching program versions, not as a hardened parser for adversarial input, so it is the wrong choice for a public HTTP endpoint regardless of the field-control issue.

## Source

`r.Body` in `importAccountHandler` (`net/http.Request.Body`) - the raw, attacker-controlled body of the POST to `/import-account`.

## Fix

The fix keeps a self-describing wire format (this endpoint defines its own contract; no other producer needs to keep speaking gob) but removes the direct client control over `IsAdmin`: decode into a request DTO that only exposes the fields a client is allowed to supply, reject unknown fields, cap the body size, validate the input, and build the trusted `Account` value on the server side with `IsAdmin` always set to `false` (new imports are never admins by policy).

### File: GobDecodeUntrustedPayload.go

```go
package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
)

type Account struct {
	Username string
	Balance  int
	IsAdmin  bool
}

// importAccountRequest is the wire-format DTO for the public endpoint. It
// intentionally omits IsAdmin: that field is a trust boundary the client
// must never be able to set directly.
type importAccountRequest struct {
	Username string `json:"username"`
	Balance  int    `json:"balance"`
}

const maxImportBodyBytes = 1 << 16 // 64 KiB is ample for this payload shape

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxImportBodyBytes)

	var req importAccountRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	if err := validateImportAccountRequest(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	account := Account{
		Username: req.Username,
		Balance:  req.Balance,
		IsAdmin:  false, // server-assigned; never taken from client input
	}

	saveAccount(account)
	w.WriteHeader(http.StatusOK)
}

func validateImportAccountRequest(req importAccountRequest) error {
	if strings.TrimSpace(req.Username) == "" {
		return errors.New("username is required")
	}
	if req.Balance < 0 {
		return errors.New("balance must not be negative")
	}
	return nil
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

- The dangerous mechanism was letting the deserializer populate a struct that mixes client-supplied data with a server-trust field (`IsAdmin`) in one step, using a format (`gob`) that has no concept of which fields a caller should be allowed to set.
- The fix decodes into a narrow DTO (`importAccountRequest`) that only contains the fields the client is entitled to provide. `IsAdmin` does not exist on that type, so there is no gob/JSON path by which a request body can influence it - it is hard-coded to `false` when the trusted `Account` is constructed.
- `json.Decoder.DisallowUnknownFields()` rejects a body that tries to smuggle an `is_admin`-shaped key rather than silently ignoring it, so a probing attacker gets an explicit 400 instead of confirmation-by-silence.
- `http.MaxBytesReader` bounds how much of the body the decoder will read, closing the resource-exhaustion angle that comes from decoding an unbounded stream from an untrusted client (this applies to `gob` too, but JSON with a bounded reader keeps the same protection with a format that also has broad tooling for schema validation).
- `validateImportAccountRequest` rejects an empty username and a negative balance - basic input validation on the fields the client does legitimately control, separate from (and in addition to) the authorization fix above.
- This does not change the trust boundary for any other consumer: nothing else in this codebase decodes `Account` from gob, so there is no producer left speaking a format this change breaks.
