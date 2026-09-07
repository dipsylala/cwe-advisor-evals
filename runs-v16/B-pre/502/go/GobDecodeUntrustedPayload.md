## Verdict

Exploitable. The `gob.NewDecoder(r.Body).Decode(&account)` call at line 19 deserializes an untrusted HTTP request body directly into the domain `Account` struct, allowing an attacker to set privileged fields like `IsAdmin` and `Balance` from client-supplied data.

## Source

Untrusted gob-encoded payload in HTTP request body (`r.Body`).

## Fix

**Vulnerable code (line 15-26):**
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
}

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	var req AccountRequest

	if err := gob.NewDecoder(r.Body).Decode(&req); err != nil {
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
```

## Explanation

The fix introduces a narrow request DTO (`AccountRequest`) containing only the `Username` field that clients are permitted to set. The gob decoder now populates this DTO instead of the full domain struct. After deserialization, the handler explicitly constructs an `Account` with privileged fields (`IsAdmin`, `Balance`) set to safe server-controlled defaults. This prevents an attacker from manipulating the serialized gob payload to inject unauthorized privilege escalation or balance modifications. The fix preserves gob as the wire format (avoiding a breaking change to existing producers) while restricting what fields can be populated from untrusted data by using type safety at the point of deserialization.

## Behaviour changes

- `IsAdmin` is now always initialized to `false` from the server rather than from client input. Callers expecting admin status to come from the request will fail silently—they must now obtain it from an authorization check or database lookup instead.
- `Balance` is now always initialized to `0` rather than from client input. Any logic depending on an initial balance from the request must fetch it from the database or other trusted source.
- The gob wire format remains unchanged; existing producers do not need to be updated. The only change is the schema of the object being decoded into.
