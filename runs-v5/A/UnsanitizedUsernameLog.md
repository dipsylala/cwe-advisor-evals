## Verdict
Confirmed. `username` is taken directly from the untrusted query string `r.URL.Query().Get("username")` and passed into `log.Printf` with no neutralization of newline or control characters, allowing log forging/injection (CWE-117).

## Source
`e:/Github/cwe-advisor/evals/cases/117/go/UnsanitizedUsernameLog/UnsanitizedUsernameLog.go`, line 10: `username := r.URL.Query().Get("username")`. This value flows unmodified into the `log.Printf` call at line 14. An attacker can set `username` to a value containing `\r` or `\n` (e.g. `attacker%0d%0aFailed login attempt for user: admin`) to inject fabricated log lines or corrupt log parsing/monitoring.

## Fix
```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	if !authenticate(username) {
		log.Printf("Failed login attempt for user: %s", strconv.Quote(username))
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "welcome, %s", username)
}

func authenticate(username string) bool {
	return false
}

func main() {
	http.HandleFunc("/login", loginHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## Explanation
`strconv.Quote` escapes `\r`, `\n`, and other non-printable/control characters into their Go-syntax escape sequences (e.g. `\r` becomes the two-character sequence `\r`, not a raw carriage return) and wraps the result in double quotes. This guarantees the logged value can never span multiple lines or inject characters that a log viewer, SIEM, or downstream parser would interpret as line boundaries or control sequences, regardless of what the attacker supplies in the `username` query parameter. Applying the quoting at the log call site (rather than mutating `username` itself) keeps the value used elsewhere - such as the `fmt.Fprintf` response at line 19 - unaffected, since that is a different sink with different neutralization requirements (HTML/response encoding, not log encoding). Any other `log.Printf`/`log.Println`/`log.Fatal`-style call in this codebase that interpolates request-derived strings should get the same treatment.
