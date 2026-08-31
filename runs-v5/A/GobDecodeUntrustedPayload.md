## Verdict

Confirmed. `importAccountHandler` feeds the raw, unauthenticated HTTP request body directly into `gob.NewDecoder(r.Body).Decode(&account)`. `encoding/gob` is a Go-to-Go wire format designed for communication between trusted peers that already agree on the type; its decoder is not hardened against hostile input and offers no way to restrict which fields a sender may set. Decoding attacker-controlled bytes straight into the privileged `Account` struct additionally lets the caller set `IsAdmin: true` directly, so the finding is both an unsafe-deserialization and a mass-assignment issue in the same line.

## Source

`r.Body` in `importAccountHandler` (`net/http.Request.Body`) — the raw body of an incoming HTTP POST to `/import-account`, fully attacker-controlled, with no authentication or size limit applied before it reaches the decoder.

## Fix

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

// accountImportRequest is the client-controlled shape. It deliberately omits
// IsAdmin (and any other privileged field) so a request body can never set
// it, regardless of what JSON keys the caller sends.
type accountImportRequest struct {
	Username string `json:"username"`
	Balance  int    `json:"balance"`
}

const maxImportBodyBytes = 1 << 16 // 64 KiB, generous for this payload shape

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxImportBodyBytes)

	var req accountImportRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	account := Account{
		Username: req.Username,
		Balance:  req.Balance,
		IsAdmin:  false, // never derived from client input
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

Two changes remove the weakness rather than just relocating it:

- **Format swap, `gob` to `json`.** `encoding/gob` was built for trusted Go-to-Go RPC where both sides share source-level type information and are not adversarial toward each other; nothing in its decoder is designed to resist a hostile sender crafting the wire bytes by hand. `encoding/json` is a plain, self-describing text format with no such trust assumption, and pairing it with `dec.DisallowUnknownFields()` makes any field the client sends that isn't explicitly expected a hard decode error instead of being silently accepted.
- **Decode into a request-scoped DTO, not the domain struct.** `accountImportRequest` only has `Username` and `Balance`. There is no `IsAdmin` field for the decoder to populate, so no request body — however crafted — can flip it. The handler sets `IsAdmin: false` explicitly when it builds the real `Account`, so privilege escalation via the deserializer is structurally impossible rather than merely unlikely. If an authenticated admin-only path ever needs to set `IsAdmin`, it should do so through a separate, authorized code path, not this import endpoint.
- **`http.MaxBytesReader` bounds the body.** This caps the amount of data the decoder will ever read from an untrusted, unauthenticated caller, closing off resource-exhaustion attempts via an oversized body before they reach the decode step.

Together these ensure the deserializer only ever produces the fields the client is meant to control, over a bounded, self-describing format, with the security-relevant field always assigned server-side.
