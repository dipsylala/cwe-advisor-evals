## Verdict

The vulnerability is **confirmed**. Line 14 logs untrusted user input (`username` from `r.URL.Query().Get("username")`) directly into the log message using `log.Printf()`, allowing log injection attacks where an attacker can inject newlines, carriage returns, or ANSI escape codes to forge log entries or manipulate log output.

## Source

File: `UnsanitizedUsernameLog.go`
Line: 14
Vulnerable code:
```go
log.Printf("Failed login attempt for user: %s", username)
```

The `username` parameter originates from untrusted user input (HTTP query parameter on line 10: `r.URL.Query().Get("username")`). This untrusted value flows directly into the log message string without any encoding or sanitization, creating a log injection sink.

## Fix

### File: UnsanitizedUsernameLog.go

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
		slog.Error("Failed login attempt for user", slog.String("user", username))
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

The fix converts the legacy `log.Printf()` call to Go's structured logging API (`log/slog`), available in Go 1.21+. Instead of concatenating the untrusted `username` into the message string, the value is passed as a typed structured attribute using `slog.String("user", username)`.

**Why this fixes the vulnerability:**

1. **Structured attributes escape control characters**: The `slog` package automatically escapes ASCII control characters (0x00–0x1F and 0x7F) in attribute values under all handlers (TextHandler, JSONHandler, and the default). This includes newlines (`\n`), carriage returns (`\r`), and escape sequences, preventing an attacker from forging log entries.

2. **Data-structure separation**: By moving the untrusted value into an attribute rather than interpolating it into the message string, the sink maintains separation between the log structure (template) and the data, allowing the handler to apply proper escaping.

3. **Handler-agnostic fix**: The escaping applies regardless of which handler is configured (text or JSON), so this fix is robust even if the logging backend changes later.

The change requires adding `"log/slog"` to the imports and modifying the logging call on line 14. The rest of the code remains unchanged.

## Behaviour changes

- **Log output format**: Changes from a simple formatted string to structured key-value pairs. Example:
  - Before: `Failed login attempt for user: attacker`
  - After: `time=2024-01-01T12:00:00.000Z level=ERROR msg="Failed login attempt for user" user=attacker`

- **Log injection now blocked**: Attempting to inject control characters or newlines results in them being escaped in the output. Example:
  - Before (vulnerable): Injecting `\n` allows creating fake log lines
  - After (fixed): Injecting `\n` produces escaped output: `user="attacker\nForged Entry"`

- **Legitimate values preserved**: Non-malicious usernames with special characters (quotes, apostrophes, etc.) continue to log correctly as escaped values in the structured format.

- **No impact on authentication logic**: The fix is purely in the logging layer; authentication behavior remains unchanged.
