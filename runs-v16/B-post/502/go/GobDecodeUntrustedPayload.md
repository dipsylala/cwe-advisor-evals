## Verdict

Exploitable. The application deserializes untrusted gob-encoded data from an HTTP request body directly into the `Account` struct without validation, allowing attackers to set the privileged `IsAdmin` field to arbitrary values.

## Source

HTTP request body (`r.Body`). The attacker supplies a gob-encoded payload via a POST request to `/import-account`.

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
// Narrow request DTO containing only client-settable fields
type AccountRequest struct {
	Username string
}

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	var req AccountRequest

	// Decode into narrower DTO instead of the full Account struct
	if err := gob.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Construct Account server-side with IsAdmin determined by authorization logic
	account := Account{
		Username: req.Username,
		Balance:  0, // or fetch from database
		IsAdmin:  checkAdminPermissions(r.Context()),
	}

	saveAccount(account)
	w.WriteHeader(http.StatusOK)
}

func checkAdminPermissions(ctx context.Context) bool {
	// Resolve admin status from session, JWT claims, database lookup, etc.
	// Never from deserialized request data
	return false // or appropriate server-side check
}
```

## Explanation

The fix replaces the deserialization sink with a narrower request struct (`AccountRequest`) that contains only the `Username` field—the only data the client should control. The gob decoder now populates this restricted DTO instead of the full `Account` struct. After deserialization, the application explicitly constructs the `Account` object on the server side, resolving privileged fields (`IsAdmin`, `Balance`) from server-side authorization logic or database lookups rather than the untrusted input. This pattern keeps the gob format intact (avoiding a breaking change to existing producers) while preventing attackers from manipulating privileged fields through the deserialized payload.

## Behaviour changes

- The `Decode` call target changed from `&account` (full struct with privileged fields) to `&req` (request DTO containing only `Username`).
- An explicit `Account` construction step is added after deserialization, with `IsAdmin` determined by `checkAdminPermissions(r.Context())` instead of the client-supplied value. This introduces a function call that resolves authorization server-side; the original code assumed all fields could come from the payload.
- `Balance` is now set server-side (example shows `0`; in production this would be fetched from a database or initialized based on business logic) rather than deserialized from the request.
- The HTTP handler now calls `checkAdminPermissions(r.Context())` to determine admin status; the original code had no such check. This is the core security fix—privileged state can no longer be forged by the client.

