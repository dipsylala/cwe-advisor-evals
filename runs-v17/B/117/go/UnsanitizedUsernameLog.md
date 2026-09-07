## Verdict

CONFIRMED. The `username` parameter from an HTTP query string (line 10) reaches an unencoded log sink (line 14) via `log.Printf`, allowing injection of newlines and ANSI escape codes. The vulnerability permits forging log entries and obscuring legitimate activity.

## Source

Line 10: `username := r.URL.Query().Get("username")` - untrusted HTTP query parameter.

## Fix

### File: UnsanitizedUsernameLog.go

```go
package main

import (
	"fmt"
	"log/slog"
	"net/http"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	if !authenticate(username) {
		// Fixed: use slog.Error with username as a structured attribute
		slog.Error("Failed login attempt", slog.String("user", username))
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "welcome, %s", username)
}

func authenticate(username string) bool {
	return false
}

func main() {
	http.ListenAndServe(":8080", nil)
}
```

## Explanation

The fix replaces the legacy `log.Printf` call with `slog.Error()` and moves the untrusted `username` from the message template string to a structured attribute via `slog.String("user", username)`. The `slog` package (available in Go 1.21+) automatically escapes ASCII control characters (including newlines, carriage returns, and ESC bytes) in attribute values, regardless of the configured handler (`TextHandler` or `JSONHandler`). This prevents attackers from injecting newlines to forge additional log entries or embedding ANSI escape sequences to manipulate log output or clear the console. The fix closes the reported finding while preserving the existing log behavior under the default handler.

## Behaviour changes

- The log output format changes from `Failed login attempt for user: <username>` to structured key-value output (e.g., `time=2026-09-07T... level=ERROR msg="Failed login attempt" user=<username>`).
- Newlines and other control characters in the username are escaped in the output (e.g., `\n` displayed as `\n` rather than a literal newline), making injection attempts visible to auditors.
- The logging package is upgraded from `log` to `log/slog`, requiring Go 1.21+. This is a language standard library change with no external dependency.
