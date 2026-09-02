## Verdict

Confirmed. `importAccountHandler` runs `gob.NewDecoder(r.Body).Decode(&account)` directly against the raw, unauthenticated HTTP request body. `encoding/gob` is a Go-native binary format with no schema validation at the wire level: the decoder trusts type and length information supplied by the sender and populates every exported field of `Account` from it, including `IsAdmin`. A client can therefore submit a crafted gob stream that sets `IsAdmin: true` on an account it should never have admin rights on, and `saveAccount` persists that value without any independent authorization check. The decoder is also unbounded - `r.Body` is read to completion with no size limit, so an attacker can force excessive memory allocation from a small request (gob pre-allocates slices/maps based on attacker-supplied length prefixes).

## Source

`r.Body` (the HTTP request body of `POST /import-account`) - fully attacker-controlled, unauthenticated network input - flows unmodified into `gob.NewDecoder(r.Body).Decode(&account)` at line 19, which sets every field of `account`, including the privilege field `IsAdmin`, before it reaches `saveAccount`.

## Fix

```go
package main

import (
	"encoding/json"
	"log"
	"net/http"
)

// accountImportRequest carries only the fields a client is allowed to
// supply. IsAdmin is intentionally absent: privilege is never taken from
// client-submitted data.
type accountImportRequest struct {
	Username string `json:"username"`
	Balance  int    `json:"balance"`
}

type Account struct {
	Username string
	Balance  int
	IsAdmin  bool
}

const maxImportBodyBytes = 1 << 16 // 64 KiB

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxImportBodyBytes)

	var req accountImportRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// IsAdmin is always derived server-side (false for a self-service
	// import), never taken from the request.
	account := Account{
		Username: req.Username,
		Balance:  req.Balance,
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

The fix removes `encoding/gob` from the request path entirely and replaces it with two independent controls that address the two distinct risks in the original code:

- **Untrusted deserialization surface**: instead of decoding straight into the domain type `Account`, the handler decodes into a narrow `accountImportRequest` DTO that only contains the fields a client is legitimately allowed to set (`Username`, `Balance`). `json.Decoder.DisallowUnknownFields()` rejects any payload that tries to smuggle in extra keys such as `is_admin`, so the attack surface is limited to exactly the fields the API contract declares.
- **Privilege field is never populated from input**: `Account.IsAdmin` is set explicitly to `false` (or, in a real system, derived from the authenticated caller's own role) inside the handler rather than being copied from decoded data. This closes the mass-assignment path even if a future field were added to the DTO by mistake, because the domain struct is still built field-by-field rather than by decoding directly into it.
- **Resource exhaustion**: `http.MaxBytesReader` caps the body at 64 KiB before decoding starts, so a malicious client can no longer force unbounded allocation via a crafted length-prefixed stream, and the JSON decoder itself performs incremental, bounds-checked parsing rather than gob's type-directed allocation.

`encoding/json` was chosen over continuing to use `encoding/gob` because gob was designed for trusted Go-to-Go RPC between processes that share a binary and a compiled-in schema, not for parsing payloads from external, potentially hostile clients; JSON with strict field decoding gives the same "decode into a struct" ergonomics while being safe to expose on a public HTTP endpoint. If a non-JSON wire format is required, apply the same two controls (a request-scoped DTO without privileged fields, and body size limiting) to whichever decoder is used.
