## Verdict

Exploitable. An attacker can send gob-encoded data to the `/import-account` endpoint that sets the privileged fields `IsAdmin` and `Balance` to arbitrary values, bypassing server-side authorization and financial controls.

## Source

Untrusted HTTP request body (`r.Body`) sent by client to the `/import-account` endpoint.

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

// AccountRequest is a narrow DTO containing only client-settable fields
type AccountRequest struct {
	Username string
}

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	var accountReq AccountRequest

	// Decode untrusted data into the narrow request DTO only
	if err := gob.NewDecoder(r.Body).Decode(&accountReq); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Construct the Account with server-side defaults for privileged fields
	account := Account{
		Username: accountReq.Username,
		Balance:  0,     // Server-side default
		IsAdmin:  false, // Server-side default
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

The vulnerability was that the gob decoder populated all fields of the `Account` struct directly from untrusted input, including the privileged fields `IsAdmin` and `Balance`. An attacker could craft a gob-encoded payload that set these fields to arbitrary values.

The fix creates a narrow request data-transfer object (`AccountRequest`) that contains only the client-settable field (`Username`). The gob decoder now targets this narrow struct instead of the full `Account`. Since gob decodes only the fields present in the destination type, the `IsAdmin` and `Balance` fields in the payload are silently ignored. The `Account` object is then constructed explicitly, with privileged fields set to server-side defaults (`IsAdmin: false`, `Balance: 0`). This follows the Go-specific CWE-502 guidance: decode untrusted data into a purpose-built request DTO containing only client-settable fields, then resolve privileged values server-side.

## Behaviour changes

The wire format remains gob (no breaking change to producers). The decoded struct type changes from `Account` to `AccountRequest`, and an intermediate `accountReq` variable is introduced. The `Account` object construction is now explicit rather than implicit from decoding, with privileged fields hardcoded to safe defaults. This ensures attackers cannot manipulate authorization state or financial data through the deserialization vector. The error handling and HTTP response behavior remain identical.
