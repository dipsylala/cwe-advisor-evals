package evalcases

import (
	"fmt"
	"math/rand/v2"
	"net/http"
)

const keyAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

var apiKeys = map[string]string{}

// IssueAPIKey mints a long-lived API key for the named account.
func IssueAPIKey(w http.ResponseWriter, r *http.Request) {
	account := r.FormValue("account")
	if account == "" {
		http.Error(w, "account required", http.StatusBadRequest)
		return
	}

	key := make([]byte, 32)
	for i := range key {
		// SAST FINDING: CWE-338 (Use of Cryptographically Weak PRNG) reported here. Sink is the next statement.
		key[i] = keyAlphabet[rand.IntN(len(keyAlphabet))]
	}

	apiKeys[string(key)] = account
	fmt.Fprint(w, string(key))
}
