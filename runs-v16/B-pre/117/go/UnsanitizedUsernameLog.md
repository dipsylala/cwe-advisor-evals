## Verdict

Exploitable. Untrusted input flows directly from the HTTP query parameter to a logging statement without encoding, allowing log injection.

## Source

Line 10: `username := r.URL.Query().Get("username")` — username is obtained directly from the URL query string, which is entirely attacker-controlled.

## Fix

Replace the legacy `log.Printf()` call with structured logging using `log/slog`. Pass the untrusted value as a typed attribute instead of concatenating it into the message string.

**Original code (lines 3–14):**
```go
import (
	"fmt"
	"log"
	"net/http"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	if !authenticate(username) {
		log.Printf("Failed login attempt for user: %s", username)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
```

**Fixed code:**
```go
import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	if !authenticate(username) {
		slog.Error("Failed login attempt", slog.String("user", username))
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
```

**Changes:**
- Add `"log/slog"` to imports (line 5).
- Replace `log.Printf("Failed login attempt for user: %s", username)` with `slog.Error("Failed login attempt", slog.String("user", username))` (line 14).

## Explanation

The vulnerability occurs because `log.Printf()` concatenates the untrusted username directly into the message string. An attacker can inject newlines (`\n`), carriage returns (`\r`), or ANSI escape sequences (e.g., `\x1b[2J`) to forge log entries or manipulate terminal output.

The fix moves the untrusted value from the message template into a structured attribute using `slog.String("user", username)`. The `log/slog` package (Go 1.21+) escapes the ASCII control character range — including newlines, carriage returns, and ESC (U+001B) — in all attribute values, regardless of which handler is configured (plain text or JSON). This escaping prevents the attacker's payload from breaking out of the data field and forging log structure.

By using `slog.Error()` instead of `log.Printf()`, the log message format is also separated from the data, making the intent clearer and allowing log aggregators to parse structured fields reliably.

## Behaviour changes

**Before the fix:**
- A login attempt with `username=attacker%0AFailed+login+attempt+for+user:+admin` produces two log lines:
  ```
  Failed login attempt for user: attacker
  Failed login attempt for user: admin
  ```
- An ANSI escape injection like `username=attacker%1b%5b2J` can clear terminal output.

**After the fix:**
- The same malicious input is logged as a single, properly escaped attribute:
  ```
  2026-09-04T12:34:56.789Z	ERROR	Failed login attempt	user=attacker\nFailed login attempt for user: admin
  ```
  or (under a JSON handler):
  ```json
  {"time":"2026-09-04T12:34:56.789Z","level":"ERROR","msg":"Failed login attempt","user":"attacker\nFailed login attempt for user: admin"}
  ```
- The newline and escape sequence are visible as literal escaped characters in the log output, not as control characters. The log entry structure is preserved, and the injection attempt is visible to incident responders.

**Legitimate usernames are unaffected:**
- A username like `alice@example.com` is logged as-is (no change in readability).
- A username containing ordinary punctuation (e.g., `user.name`, `user-123`) appears unchanged.

