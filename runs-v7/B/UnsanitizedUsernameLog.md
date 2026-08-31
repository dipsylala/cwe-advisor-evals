## Verdict

Exploitable. The untrusted `username` parameter flows from an HTTP query string directly into a `log.Printf()` call without encoding, allowing log injection attacks (newlines, carriage returns, ANSI escape sequences).

## Source

Line 10: `username := r.URL.Query().Get("username")` - untrusted HTTP query parameter

## Fix

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

The fix moves the untrusted `username` from the message string into a structured attribute passed to `slog.Info()`. Go 1.21+ `log/slog` automatically escapes ASCII control characters (including newlines and carriage returns) in attribute values under all handlers (text, JSON, or custom). This prevents an attacker from injecting `\n` or `\r\n` to forge log entries or hide malicious activity. The message string remains under application control while the user-supplied data travels through the handler's sanitization layer.

## Behaviour changes

- Import changes: `"log"` removed, `"log/slog"` added
- Logging call changes from `log.Printf()` (legacy package) to `slog.Info()` (structured logging)
- Log output format differs: from text interpolation to structured key-value pairs (e.g., `time=... level=INFO msg="Failed login attempt" user=attacker` with control chars escaped)
- The message is now static and not dependent on runtime values, improving log parsing and auditing

