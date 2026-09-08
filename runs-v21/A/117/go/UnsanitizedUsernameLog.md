## Verdict

The log message on line 14 passes unsanitized user input directly to `log.Printf()`. An attacker can inject newlines and control characters to create fake log entries, hide real log entries, or manipulate the output stream. This violates CWE-117 by failing to neutralize log-control characters.

## Source

```
username := r.URL.Query().Get("username")  // Line 10: attacker-controlled
log.Printf("Failed login attempt for user: %s", username)  // Line 14: sink
```

The attacker controls `username` through the query string and can inject newlines, carriage returns, and other control characters.

## Fix

### File: UnsanitizedUsernameLog.go

```go
package main

import (
	"fmt"
	"log"
	"net/http"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	if !authenticate(username) {
		log.Printf("Failed login attempt for user: %q", username)
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

Line 14 is changed from `%s` to `%q`. The `%q` format verb quotes the string and escapes special characters including newlines, tabs, carriage returns, and control characters. This prevents an attacker from injecting log-control characters via the username parameter.

Example behavior:
- Input: `admin\nFaked entry\n`
- With `%s`: Creates multiple log lines (vulnerable)
- With `%q`: Outputs `"admin\nFaked entry\n"` as a single quoted string (safe)

The `%q` verb is Go's idiomatic defense against log injection and is part of the standard library with no external dependencies.
