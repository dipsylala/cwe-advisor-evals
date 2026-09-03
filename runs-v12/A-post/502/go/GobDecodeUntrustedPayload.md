## Verdict

CWE-502 confirmed. The code deserializes untrusted binary data from an HTTP request body using `encoding/gob` without any validation or signature verification, allowing an attacker to inject arbitrary field values including `IsAdmin`.

## Source

The vulnerable code path: HTTP request handler → `gob.NewDecoder(r.Body).Decode(&account)` → untrusted fields written directly to `Account` struct → account data used in `saveAccount()` without re-validation.

The attacker can craft a malicious gob-encoded payload that sets `Username` to any value and `IsAdmin` to `true`, granting themselves admin privileges.

## Fix

Replace `encoding/gob` deserialization with `encoding/json` and add explicit validation that prevents untrusted sources from setting the `IsAdmin` field:

```go
package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type Account struct {
	Username string `json:"username"`
	Balance  int    `json:"balance"`
	IsAdmin  bool   `json:"-"` // Never deserialize from untrusted input
}

type AccountInput struct {
	Username string `json:"username"`
	Balance  int    `json:"balance"`
	// Intentionally omit IsAdmin to prevent untrusted assignment
}

func importAccountHandler(w http.ResponseWriter, r *http.Request) {
	var input AccountInput

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Validate input and construct Account with controlled field values
	if input.Username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}

	account := Account{
		Username: input.Username,
		Balance:  input.Balance,
		IsAdmin:  false, // Always start as non-admin; only internal systems set this
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

**Why the original code is vulnerable:** `encoding/gob` is a binary serialization format that preserves the full Go type information, allowing an attacker to craft a payload that sets any struct field to any value. Gob has no built-in authentication and cannot be safely used with untrusted input.

**Why the fix works:**

1. **Switch to JSON:** `encoding/json` requires field tags and is more predictable. Combined with a separate input struct, it blocks unwanted fields.

2. **Use an input struct:** `AccountInput` omits the `IsAdmin` field entirely, making it structurally impossible for untrusted JSON to assign to it. The handler then constructs the full `Account` struct with `IsAdmin` hardcoded to `false`.

3. **Mark sensitive fields:** The `json:"-"` tag on `IsAdmin` in the main struct provides defense-in-depth, ensuring it is never deserialized even if the struct definition is accidentally changed.

4. **Validate required fields:** The handler checks that `Username` is not empty before proceeding.

5. **Explicit construction:** By explicitly assigning field values in the handler after validation, only the handler logic can control whether an account is created with admin privileges.

If admin assignment must be supported later, add a separate, authenticated admin API endpoint that explicitly calls a function to grant privileges, rather than allowing untrusted input to control it.
