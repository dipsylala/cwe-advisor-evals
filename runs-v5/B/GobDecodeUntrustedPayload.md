## Verdict

- **CWE-502** (Deserialization of Untrusted Data) - **exploitable**
- **Location**: `GobDecodeUntrustedPayload.go`, line 19 - `gob.NewDecoder(r.Body).Decode(&account)`
- **Confidence**: high

## Source

- **Source**: `r.Body` in `importAccountHandler`, the raw, unauthenticated body of an HTTP POST to `/import-account` (registered via `http.HandleFunc` in `main`).
- **Sink**: `gob.NewDecoder(r.Body).Decode(&account)` at line 19. `encoding/gob` populates every exported field of `Account` - including `Balance` and the privileged `IsAdmin` flag - by reflection, directly from the wire, with no schema or integrity check.
- **Flow**: the decoded `account` value is passed unchanged to `saveAccount(account)` at line 24, which logs and (per its name) persists it, so the attacker-supplied `IsAdmin`/`Balance` values flow straight into application state. No validation, allowlist, or authorization check sits between decode and use, so the path is live end to end.
- **Sink contract** (`gob.Decode`): returns an `error`, checked and mapped to HTTP 400 on failure. On success it discards nothing - every field it sets is exported into `account`. Body size is left implicit/unbounded (no `http.MaxBytesReader`). No type whitelisting: any registered field can be set to any value valid for its Go type.

## Fix

No third-party library is needed; the fix uses the standard library's `encoding/json` in place of `encoding/gob`, per `cwe/502/go/INDEX.md`.

Vulnerable code:

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

	// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
	if err := gob.NewDecoder(r.Body).Decode(&account); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
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

Fixed code:

```go
package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

type Account struct {
	Username string
	Balance  int
	IsAdmin  bool
}

// importAccountRequest is the client-settable subset of Account. Privileged
// fields (IsAdmin) are deliberately absent so they can never be set from
// the wire.
type importAccountRequest struct {
	Username string `json:"username"`
	Balance  int    `json:"balance"`
}

const maxImportAccountBodyBytes = 1 << 20 // 1 MiB

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxImportAccountBodyBytes)

	var req importAccountRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	if err := validateImportAccountRequest(req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	account := Account{
		Username: req.Username,
		Balance:  req.Balance,
		IsAdmin:  false, // privileged field: never taken from client input
	}

	saveAccount(account)
	w.WriteHeader(http.StatusOK)
}

func validateImportAccountRequest(req importAccountRequest) error {
	if req.Username == "" {
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

The vulnerability is that `encoding/gob` reconstructs `Account` by reflection straight from the request body, so an attacker can set every exported field - including the privileged `IsAdmin` flag - with no validation or integrity check. The fix replaces `gob` with `encoding/json` decoding into a purpose-built `importAccountRequest` DTO that has no `IsAdmin` field at all, so that value cannot be supplied by the client under any circumstance; `DisallowUnknownFields()` makes an attempt to smuggle an `isAdmin` field fail the decode outright rather than being silently ignored. The trusted `Account` is then built explicitly from the validated request fields plus a hard-coded, server-controlled `IsAdmin: false`, breaking taint before the privileged field reaches `saveAccount`. A `Validate()`-style check and an `http.MaxBytesReader` cap round out the fix per the loaded Go guidance, closing the field-level and resource-exhaustion gaps that `gob` decoding left open.

## Behaviour changes

- **Wire format changed from gob to JSON.** This is not incidental - `encoding/gob` is itself the vulnerable sink and the Go guidance's primary fix is to avoid it entirely on untrusted input, so any client of this endpoint must now send JSON instead of a gob-encoded payload.
- **`IsAdmin` can no longer be set by the request; it is always `false` in this handler.** Previously any caller could set it directly. This is the security fix itself (privileged fields must come from server-side authorization, never client input), not incidental scope creep - but it does mean the endpoint as given has no path to create an admin account, since `Account.IsAdmin` is hard-coded. If admin provisioning through this endpoint is a real requirement, that decision has to be made by a separate, authorization-checked code path, not restored here.
- **Unknown/extra JSON fields (e.g. a submitted `isAdmin` key) now cause the request to be rejected with 400** instead of being silently accepted or ignored, via `DisallowUnknownFields()`.
- **New validation rejects requests with an empty `Username` or a negative `Balance`** with 400. The original `gob` path performed no such validation and would accept any values valid for the Go types (including negative balances).
- **Request bodies over 1 MiB are now rejected.** The original code read `r.Body` with no size limit. The 1 MiB figure is not from the loaded guidance (which prescribes the mechanism, `http.MaxBytesReader`, but not a specific limit) and should be reviewed against the endpoint's real expected payload size.

**Assumption**: `saveAccount` was treated as the trust boundary/persistence point (per its name and the finding's framing of "1 file forming the call chain") rather than traced into a deeper implementation, since no further definition is present in the provided file.
