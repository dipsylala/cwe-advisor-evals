## Verdict

Exploitable. Confidence: high.

- **cwe_id**: CWE-502 (Deserialization of Untrusted Data)
- **location**: `GobDecodeUntrustedPayload.go`, line 19 (`gob.NewDecoder(r.Body).Decode(&account)`)

## Source

`r.Body` in `importAccountHandler` - the raw, attacker-controlled body of an HTTP POST to `/import-account`. Nothing upstream authenticates the caller or constrains the body content before it reaches the decoder.

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

// AccountImportRequest carries only the fields a client may set when
// importing an account. Privileged fields (Balance, IsAdmin) are resolved
// server-side and are never decoded from the request.
type AccountImportRequest struct {
	Username string
}

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	var req AccountImportRequest

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // cap decoded payload at 1 MiB

	if err := gob.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Privileged fields are set server-side, never taken from client input.
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

The handler gob-decoded the request body directly into `Account`, the same struct that carries the privileged `Balance` and `IsAdmin` fields later persisted by `saveAccount`. Since `gob` populates every field present by name in its destination type, an attacker who gob-encodes `{Username, Balance, IsAdmin}` can set `IsAdmin=true` and any `Balance` value, and the handler saves it verbatim - no code execution, but a straight authorization bypass via the deserialized object. The fix keeps `gob` and the existing `Decode(&x)` call shape (per the Go guidance, the destination type is the fix, not the wire format) but points it at a new `AccountImportRequest` struct that contains only the one client-settable field, `Username`. `gob` decodes only fields present in the destination type, so the sender's `Balance`/`IsAdmin` bytes are never populated into anything and are silently dropped by the decoder itself. `Balance` and `IsAdmin` on the persisted `Account` are now always server-assigned constants (`0` / `false`) rather than attacker-supplied, closing the privileged-field vector without touching what any producer sends on the wire.

## Behaviour changes

- **Destination type narrowed** (`Account` -> `AccountImportRequest`) at the decode site: any gob payload that previously set `Balance`/`IsAdmin` now has those bytes silently ignored by the decoder (unchanged gob semantics - extra fields in the source not present in the destination are dropped) rather than applied. This is the fix itself, not incidental.
- **`Balance` and `IsAdmin` now always `0`/`false`** on every imported account, since no server-side source of truth for these fields exists in this handler. This is a functional narrowing, not just a security tightening: a legitimate caller that previously could set a non-default `Balance` or `IsAdmin` via this endpoint no longer can through this path. Flagging as an assumption below - a real deployment likely needs a separate authorized path (admin API, DB-backed account state) to set these post-import, which is outside this fix's scope.
- **New empty-`Username` rejection** (400 `invalid payload`): the original accepted an empty username silently; the fix rejects it. Minor validation addition per the Go guidance's "Bind, encode, validate, or authorize" step; not required to close the CWE-502 finding itself but a low-risk, in-scope hardening of the same handler.
- **Added `http.MaxBytesReader(w, r.Body, 1<<20)`**: bounds the decoded payload to 1 MiB. Not present before. This addresses the "Harden configuration" step in the Go guidance for the same sink (unbounded body read into a decoder) and does not change behavior for any legitimately-sized payload; oversized bodies now fail the `Decode` call and return the existing 400 response rather than being read without limit.
- Everything else (route, response codes on success, `saveAccount`'s signature and logging, `main`) is unchanged.

## Assumptions

- No server-side source (DB lookup, auth context) for `Balance`/`IsAdmin` exists in this minimal handler, so the fix assigns safe defaults (`0`/`false`) rather than fabricating a lookup. A real fix would resolve these from an authorized source; this is noted as a gap rather than invented.
- 1 MiB was chosen as a reasonable request-body cap; the guidance names the mechanism (`http.MaxBytesReader`) but not a specific limit, so this value is an assumption a deployment may want to tune.

## Verification

Ran `go vet ./...` and `go build ./...` against the fixed file in an isolated scratch module (`verify`, Go 1.25.5, windows/386): both completed with no errors or diagnostics.
