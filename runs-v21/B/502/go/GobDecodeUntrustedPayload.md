## Verdict
Exploitable

## Source
Attacker-controlled HTTP request body (`r.Body`) sent via POST to `/import-account`. An attacker can craft a gob-serialized payload containing an `Account` struct with arbitrary field values.

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

type AccountRequest struct {
	Username string
}

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	var accountReq AccountRequest

	// Decode into a narrow DTO containing only client-settable fields
	if err := gob.NewDecoder(r.Body).Decode(&accountReq); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Construct the Account struct server-side with privileged fields set by the server
	account := Account{
		Username: accountReq.Username,
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
The original code deserialized untrusted gob data directly into the `Account` struct, allowing an attacker to set arbitrary fields including the privileged `IsAdmin` field. The fix creates a narrow request DTO (`AccountRequest`) containing only the `Username` field that clients are permitted to control. The gob decoder only populates fields present in the destination type, so decoding into `AccountRequest` prevents injection of `IsAdmin`, `Balance`, or other privileged fields. The `Account` struct is then constructed server-side with privileged fields (`IsAdmin` and `Balance`) set to safe defaults by the application logic, eliminating the deserialization vector for privilege escalation.

## Behaviour changes
- Added new type `AccountRequest` as a narrow request struct (not in original)
- Changed deserialization target from `Account` to `AccountRequest` (prevents field injection)
- Added explicit `Account` struct construction with server-set defaults for `Balance` (0) and `IsAdmin` (false), rather than populating from deserialized data (breaks taint path for privileged fields)
- All other function signatures and control flow remain unchanged; the `saveAccount` call and HTTP response handling are identical to the original
