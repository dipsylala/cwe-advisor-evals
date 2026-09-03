## Verdict

exploitable

## Source

`r.Body` (HTTP request body), untrusted attacker-controlled input

## Fix

**Vulnerable code (line 19):**
```go
func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	var account Account

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
type AccountRequest struct {
	Username string
}

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	limitedBody := http.MaxBytesReader(w, r.Body, 1024)
	var req AccountRequest

	if err := gob.NewDecoder(limitedBody).Decode(&req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Validate request fields
	if req.Username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}

	// Create Account with server-side defaults; privileged fields never come from the request
	account := Account{
		Username: req.Username,
		Balance:  0,
		IsAdmin:  false,
	}

	saveAccount(account)
	w.WriteHeader(http.StatusOK)
}
```

## Explanation

The original code decoded untrusted gob data directly into the `Account` struct, which contains privileged fields (`IsAdmin`, `Balance`). An attacker could craft a gob payload that sets these fields to arbitrary values. The fix introduces a narrower request DTO (`AccountRequest`) that contains only client-settable fields. Decoding into the DTO prevents attacker control over privileged fields. The `Account` object is then constructed explicitly on the server side, with `IsAdmin` and `Balance` initialized to safe defaults. The privileged fields would normally be resolved from server-side authorization checks or database lookups, not from untrusted deserialized data. The addition of `http.MaxBytesReader` provides resource-exhaustion hardening to prevent oversized payloads from being decoded.

## Behaviour changes

- **Request DTO introduced**: The handler now decodes into `AccountRequest` (only `Username`) rather than directly into `Account`. This is a necessary constraint to enforce field-level access control.
- **Payload size limit added**: `http.MaxBytesReader` with a 1 KB limit prevents resource exhaustion from oversized gob payloads. A production implementation should tune this limit based on expected `Username` length.
- **Explicit Account construction**: Rather than relying on the deserialized object, `Account` is now constructed explicitly with server-controlled defaults for `IsAdmin` (always `false`) and `Balance` (always `0`). This replaces any attacker-supplied values for these fields and ensures privileged state is never derived from untrusted input.
- **Validation added**: Empty `Username` is rejected before account creation, preventing invalid or malicious payloads from reaching `saveAccount()`.
- **Wire format preserved**: The gob encoding is unchanged; existing producers sending gob payloads continue to work with the narrower DTO. The decoder sees only the fields present in `AccountRequest` and ignores any extra gob fields (the attacker's `IsAdmin`/`Balance` fields are silently dropped).
