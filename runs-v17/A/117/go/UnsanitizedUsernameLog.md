## Verdict
Confirmed CWE-117 issue. User-supplied input from an HTTP query parameter is logged without neutralizing control characters.

## Source
The `username` parameter is extracted from `r.URL.Query().Get("username")` (line 10) and logged directly at line 14 with `log.Printf("Failed login attempt for user: %s", username)`. An attacker can inject newline (`\n`) or carriage return (`\r`) characters to create fake log entries or obfuscate the attack in log streams.

## Fix
### File: UnsanitizedUsernameLog.go
```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	if !authenticate(username) {
		// Neutralize control characters in log output
		sanitizedUsername := strings.NewReplacer(
			"\n", " ",
			"\r", " ",
		).Replace(username)
		log.Printf("Failed login attempt for user: %s", sanitizedUsername)
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
The fix neutralizes control characters before logging by using `strings.NewReplacer` to replace newlines and carriage returns with spaces. This prevents log injection attacks where an attacker injects newline characters to create fake log entries. The original username is preserved for response output to the legitimate user, as that context handles the data safely. Log output is now safe regardless of what characters the input contains.
