## Verdict

VULNERABLE. The username parameter sourced from an untrusted HTTP query string is concatenated directly into a log message without encoding, allowing an attacker to forge log entries or inject false data by including newlines, carriage returns, or ANSI escape sequences.

## Source

Line 10: `username := r.URL.Query().Get("username")` — untrusted HTTP request parameter read from the query string with no validation.

## Fix

Convert line 14 from `log.Printf("Failed login attempt for user: %s", username)` to structured logging using the `slog` package with untrusted data passed as a typed attribute:

```go
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	username := r.URL.Query().Get("username")

	if !authenticate(username) {
		logger.Error("Failed login attempt", slog.String("user", username))
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
	slog.Error("server error", slog.Any("error", http.ListenAndServe(":8080", nil)))
}
```

## Explanation

The fix moves untrusted user input from direct string concatenation into a structured `slog` attribute. Go's `slog` package (available in Go 1.21+) automatically escapes the ASCII control range (`\x00-\x1F`, `\x7F`) and Unicode line separators in attribute values under both `TextHandler` and `JSONHandler`, preventing log injection regardless of the handler in use. 

By passing the username via `slog.String("user", username)` as an attribute instead of embedding it in the message template string, the logger treats it as opaque data rather than message structure. When an attacker includes characters like `\n` or ANSI escape codes (e.g., `\x1b[2J`), they are automatically escaped to their literal representation (e.g., `\n` becomes `\\n`) in the logged output, preserving the integrity of the audit trail and preventing entry forgery.

The `logger` instance is created with `slog.NewTextHandler` as an example; it can use `NewJSONHandler` or other handlers without changing the injection safety, since structured attributes are escaped uniformly. The `os.Stderr` destination can be adjusted to match the application's logging configuration.

## Behaviour changes

- Logging format changes from a single message string to structured key-value pairs. Output that previously read `Failed login attempt for user: alice` now reads `time=... level=ERROR msg="Failed login attempt" user=alice` (TextHandler) or `{"time":"...","level":"ERROR","msg":"Failed login attempt","user":"alice"}` (JSONHandler).
- Legitimate usernames containing punctuation (e.g., `user+test@example.com`, `john.doe`) are now logged as-is without any additional escaping, improving readability for valid entries.
- Control characters and Unicode line separators in the username are escaped (e.g., attacker input `admin\nFailed login attempt for user: attacker` logs as a single event with the newline escaped), preserving the audit trail integrity.
- The output destination for the primary logger is `os.Stderr`; adjust this in `slog.NewTextHandler()` or `NewJSONHandler()` if the application requires logging to a different stream.
