## Verdict

exploitable

- **cwe_id**: CWE-117
- **location**: UnsanitizedUsernameLog.go, line 14
- **source** / **sink**: source is `r.URL.Query().Get("username")` (line 10, HTTP query parameter, attacker-controlled); sink is `log.Printf("Failed login attempt for user: %s", username)` (line 14)
- **confidence**: high
- **assumptions**: none - the finding location, language, and data flow were unambiguous

## Source

`username := r.URL.Query().Get("username")` at line 10 - an HTTP query string parameter, fully attacker-controlled. `authenticate(username)` (lines 22-24) only returns `false`; it performs no validation or sanitization of `username`, so the value reaching the sink at line 14 is exactly what the attacker supplied, including any embedded newlines, carriage returns, or ANSI escape sequences.

## Fix

**Vulnerable code:**

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
		// SAST FINDING: CWE-117 (Improper Output Neutralization for Logs) reported here. Sink is the next statement.
		log.Printf("Failed login attempt for user: %s", username)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "welcome, %s", username)
}
```

**Fixed code:**

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
		slog.Info("Failed login attempt", "user", username)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "welcome, %s", username)
}
```

`log.Fatal` in `main()` still uses the legacy `log` package, so that import is retained alongside the new `log/slog` import.

## Explanation

The vulnerable line concatenates the raw, attacker-controlled `username` directly into a `log.Printf` message string; the legacy `log` package performs no encoding, so an attacker can embed `\r\n` or ANSI escape sequences to forge additional log lines or corrupt terminal-based log viewers. The fix moves `username` out of the message string and passes it as a structured `slog` attribute (`"user", username`) instead. `slog`'s handlers - including the zero-value default `TextHandler` used here, since no handler is otherwise configured - escape the ASCII control range (including `\n`, `\r`, and ESC) in attribute values, so an injected control character is rendered as an escaped sequence rather than being interpreted as a literal line break or terminal command. This closes the finding at the reported sink without requiring a switch to JSON output; migrating to `slog.NewJSONHandler` remains a separate, optional change for machine-parseable logs, not a prerequisite for this fix.

## Behaviour changes

- Log output format changes from a plain `log.Printf` line (date/time prefix + free-text message) to `slog`'s default text-handler format (`time=... level=INFO msg="Failed login attempt" user=...`). This is a necessary consequence of moving to structured logging and is required to get the sink's automatic escaping - the message content and information logged are otherwise unchanged.
- The log now carries an explicit `level=INFO` field where the original had no level concept; `Info` was chosen as the closest equivalent to the original's unleveled `log.Printf` call, so severity semantics are preserved rather than escalated or downgraded.
- Destination is unchanged: `slog`'s default handler, like the legacy `log` package, writes to `os.Stderr`.
- No change to `authenticate()`, the HTTP response written via `http.Error`, or the `fmt.Fprintf(w, "welcome, %s", username)` line on the success path - that line is a separate sink not covered by this finding, and CWE-117 concerns log output specifically.
