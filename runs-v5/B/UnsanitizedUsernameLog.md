## Verdict

exploitable (confidence: high)

## Source

`r.URL.Query().Get("username")` (line 10 of `UnsanitizedUsernameLog.go`) - the `username` query parameter from an incoming HTTP request, fully attacker-controlled. It reaches the sink unmodified: `authenticate(username)` only returns a boolean and performs no encoding, validation, or sanitization of the value itself, so the string that fails authentication is the same string an attacker supplied.

## Fix

Vulnerable code (line 14, in `loginHandler`):

```go
log.Printf("Failed login attempt for user: %s", username)
```

Fixed code:

```go
package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	if !authenticate(username) {
		slog.Warn("Failed login attempt", "user", username)
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

The original call concatenated the untrusted `username` value straight into the log message string, so any control character it contained - `\n`, `\r`, ANSI escape sequences - was written to the log verbatim, letting an attacker forge additional log lines or corrupt terminal output for anyone tailing the log. Replacing `log.Printf` with `slog.Warn` moves `username` out of the message template and into a structured attribute (`"user", username`). Under `log/slog`'s zero-value default handler (the one in effect here, since no handler is configured), attribute values are quoted and every ASCII control byte - including newline, carriage return, and ESC - is escaped rather than written raw, which closes the forging vector without needing a JSON handler or any extra encoding call. `main()`'s unrelated `log.Fatal(http.ListenAndServe(...))` takes no user input, so it is left on the legacy `log` package.

## Behaviour changes

- Log destination is unchanged: `slog`'s default handler, like the default `log` package logger, writes to `os.Stderr`.
- Output line format changes from the plain-text message `Failed login attempt for user: <value>` to `slog`'s structured key=value text format (e.g. `level=WARN msg="Failed login attempt" user=<value>`), with the value quoted/escaped. This is inherent to the fix - the escaping that closes the injection is what produces the new format - and is a downstream-tooling change, not a functional one for this handler.
- A severity level (`Warn`) is now attached to the entry; the original `log.Printf` call had no level concept. `Warn` was chosen as an accurate, non-escalating severity for a failed login attempt; this is a byproduct of `slog`'s API requiring a level and does not change what is logged or when.
- No change to control flow, the HTTP response (`http.Error` / `StatusUnauthorized`), or the success path (`fmt.Fprintf` welcome message), which was out of scope for this finding.

## Assumptions

None requiring escalation - the loaded Go guidance directly names `log.Printf` with concatenated input as the sink and structured `slog` attributes as the fix, and no third-party library or version was needed.
