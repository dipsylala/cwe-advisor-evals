## Verdict

Real. An attacker can craft a malicious gob payload to set the `IsAdmin` field to `true` when deserializing untrusted HTTP request data, bypassing authorization and gaining admin privileges.

## Source

Line 19 of the vulnerable handler deserializes directly from the HTTP request body into a struct containing sensitive fields:

```
if err := gob.NewDecoder(r.Body).Decode(&account); err != nil {
```

The `Account` struct includes the `IsAdmin` field, which should never be settable by untrusted input. The gob decoder allows attackers to craft a payload that sets this field to `true`.

## Fix

Replace the direct deserialization with a two-step approach: deserialize only user-controllable fields into an intermediate struct, then explicitly construct the `Account` with `IsAdmin` always set to `false` for imported accounts:

```go
func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	// Intermediate struct with only user-settable fields
	var input struct {
		Username string
		Balance  int
	}
	
	if err := gob.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	
	// Explicitly construct Account, preventing attacker from setting IsAdmin
	account := Account{
		Username: input.Username,
		Balance:  input.Balance,
		IsAdmin:  false, // Always false for imported accounts
	}
	
	saveAccount(account)
	w.WriteHeader(http.StatusOK)
}
```

## Explanation

The vulnerability occurs because deserializing untrusted data directly into a struct allows attackers to set sensitive fields. By using an intermediate struct that contains only the fields an attacker is allowed to control (`Username` and `Balance`), we prevent the gob decoder from ever seeing or setting the `IsAdmin` field. We then explicitly construct the final `Account` struct with `IsAdmin` hardcoded to `false`, ensuring that untrusted input cannot elevate privileges. This approach is more maintainable than trying to validate the `IsAdmin` field after deserialization, because it makes the intent clear: only these fields come from untrusted sources.
