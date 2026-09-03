## Verdict

CONFIRMED. Untrusted user input from an HTTP query parameter is passed directly to `log.Printf()` without sanitization, enabling log injection attacks.

## Source

**Line 10 (source):** `username := r.URL.Query().Get("username")`
- Untrusted HTTP query parameter, attacker-controlled

**Line 14 (sink):** `log.Printf("Failed login attempt for user: %s", username)`
- Untrusted value concatenated directly into format string
- No encoding or validation applied
- `log.Printf()` has no built-in escaping for control characters

## Fix

Replace the legacy `log` package with Go's structured `log/slog` package (Go 1.21+), and pass the username as a typed attribute instead of concatenating it into the message string:

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
		slog.Info("Failed login attempt", slog.String("user", username))
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

The vulnerability arises from concatenating untrusted input directly into a log message. An attacker can inject newlines, carriage returns (`\r\n`), or ANSI escape sequences (e.g., `\x1b[2J`) to forge log entries, hide malicious activity, or inject false information into monitoring systems.

The fix migrates from `log.Printf()` to `slog.Info()` with structured attributes. The `slog.String()` attribute wrapper automatically escapes the ASCII control range (`\x00-\x1F`, `\x7F`) in the attribute value under every handler—the default TextHandler, JSONHandler, and custom implementations all perform this escaping. This separation of data (the username) from message structure (the log template) closes the injection vector: the untrusted value cannot contain control characters that alter the log structure.

## Behaviour changes

- The log output format changes from unstructured text to structured key-value pairs when using the default `slog` handler. The default TextHandler produces output like `time=2025-09-03T12:00:00.000Z level=INFO msg="Failed login attempt" user=attacker%27s%5Cinput`.
- Malicious payloads are now safely escaped. An attacker attempting to inject `\ninfo admin logged in` receives output with escaped newlines and backslashes, preserving evidence of the injection attempt.
- Authentication failure behavior is unchanged: invalid credentials still return HTTP 401 and no new log entries are created for successful logins.
- The application's security posture improves: log aggregation and SIEM tools can now safely parse and index log entries without risk of injection-based obfuscation.
