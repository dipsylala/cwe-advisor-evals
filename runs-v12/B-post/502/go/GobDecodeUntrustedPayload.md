## Verdict

exploitable

## Source

Untrusted HTTP request body (`r.Body`) decoded with `gob.NewDecoder(r.Body).Decode(&account)` at line 19.

## Fix

**Vulnerable code:**
```go
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
```

**Fixed code:**
```go
type AccountRequest struct {
	Username string
	Balance  int
}

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	var req AccountRequest

	if err := gob.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Construct the Account object with server-side determined IsAdmin value
	account := Account{
		Username: req.Username,
		Balance:  req.Balance,
		IsAdmin:  false, // Always set to false for imported accounts; promotion must come via server-side authorization
	}

	saveAccount(account)
	w.WriteHeader(http.StatusOK)
}
```

## Explanation

The vulnerability exists because the original code decodes untrusted gob data directly into the `Account` struct, which contains the privileged field `IsAdmin`. An attacker can craft a gob-encoded payload with `IsAdmin: true` to escalate their privileges. The fix creates a narrower `AccountRequest` struct containing only client-settable fields (`Username` and `Balance`), decodes into that struct instead, and then explicitly constructs the `Account` object with the privileged `IsAdmin` field set server-side to a safe default value. This ensures that `IsAdmin` cannot be controlled by the attacker and must be determined through a separate server-side authorization mechanism.

## Behaviour changes

The decoded object type changes from `Account` (including `IsAdmin`) to `AccountRequest` (excluding `IsAdmin`), requiring explicit construction of the `Account` struct. The resulting account always has `IsAdmin: false` on import, whereas the vulnerable code allowed attackers to set it directly. The final behavior of `saveAccount()` is unchanged—an `Account` object with the same fields is still passed—except that `IsAdmin` is now guaranteed to be false rather than attacker-controlled.
