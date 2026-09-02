## Verdict

Confirmed. Untrusted HTTP query parameter flows to a legacy `log.Printf` call without escaping, allowing log injection via newlines and control characters.

## Source

Line 10: `username := r.URL.Query().Get("username")` - HTTP query parameter, attacker-controlled.

## Fix

Replace the legacy `log.Printf` call with structured `slog` logging. The `slog` package escapes ASCII control characters (including newlines, carriage returns, and ANSI escape codes) in attribute values under every handler, eliminating the injection vector.

**Vulnerable code (line 14):**
```go
log.Printf("Failed login attempt for user: %s", username)
```

**Fixed code:**
```go
import (
	"fmt"
	"log/slog"
	"net/http"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	if !authenticate(username) {
		slog.Info("Failed login attempt", slog.String("user", username))
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "welcome, %s", username)
}
```

## Explanation

The vulnerability occurs because `log.Printf` concatenates untrusted input directly into the message string without escaping. An attacker can inject `\n` to forge new log entries, hide activity, or inject misleading information.

The fix replaces the legacy `log` package call with `slog.Info()`, passing the username as a structured attribute via `slog.String("user", username)`. The `slog` package automatically escapes the ASCII control range (including `\x00-\x1F`, `\x7F`) in attribute values regardless of which handler is configured (TextHandler, JSONHandler, or default). This separates data from structure, making injection impossible. The import statement changes from the legacy `log` package to `log/slog` (available in Go 1.21+).

## Behaviour changes

- Output format changes from plain text to structured logging (each log call now includes key-value pairs).
- Log message becomes two parts: message text ("Failed login attempt") and an attribute ("user" field). Existing log parsers expecting `Failed login attempt for user: <value>` will need to parse the structured format instead.
- Newlines and control characters in the username now appear escaped (e.g., `\n` as `\\n`), so they are visible as data rather than log control characters.
- A single log line is produced regardless of injection payload; the entry cannot be forged into multiple lines.
- Error handling behaviour is unchanged: the function still returns with HTTP 401 on authentication failure.
