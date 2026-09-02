## Verdict

exploitable (confidence: high)

CWE-502 (Deserialization of Untrusted Data) - `GobDecodeUntrustedPayload.go:19`.

## Source

The HTTP request body (`r.Body`) of `POST /import-account`, handled by `importAccountHandler`. This body is fully attacker-controlled and reaches the sink with no prior validation, size limit, or authentication check.

## Fix

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
	"log"
	"net/http"
)

type Account struct {
	Username string
	Balance  int
	IsAdmin  bool
}

// ImportAccountRequest is the client-settable subset of Account. Privileged
// fields (Balance, IsAdmin) are deliberately excluded and never sourced from
// client input.
type ImportAccountRequest struct {
	Username string `json:"username"`
}

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	var req ImportAccountRequest

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	account := Account{
		Username: req.Username,
		Balance:  0,
		IsAdmin:  false,
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

`gob.Decoder.Decode` populates every exported field of the target struct directly from the wire format with no schema or integrity check, so a client sending a gob-encoded `Account` can set `Balance` and `IsAdmin` to any value it likes, not just `Username`. The fix removes `encoding/gob` from the untrusted-input path entirely and decodes into `ImportAccountRequest`, a request-only DTO that carries just the field a client is allowed to set. `DisallowUnknownFields()` rejects a payload that tries to smuggle in `balance` or `isAdmin` as extra JSON keys instead of silently dropping them. The persistence-facing `Account` is then built explicitly from the validated `Username` plus server-determined defaults for the privileged fields, so no attacker-controlled value can reach `Balance` or `IsAdmin`.

## Behaviour changes

- Wire format changes from gob to JSON, so the client must send a JSON body (`{"username": "..."}`) instead of a gob-encoded `Account`; this is required to eliminate the arbitrary-field-population weakness, not incidental.
- A payload containing any field other than `username` (including `balance` or `isAdmin`) is now rejected with `400 invalid payload` instead of being silently accepted; this is the intended effect of closing the finding.
- `Balance` and `IsAdmin` are now always `0`/`false` for every imported account rather than taking whatever value the client supplied. No code in this file establishes an alternative source of truth (e.g. a database lookup or auth-derived role) for these fields, so the safe default is to zero them until such a mechanism is added - this is a functional change if the caller previously relied on setting a non-zero balance or admin flag via this endpoint, and that reliance was itself the vulnerability.
