## Verdict

Exploitable. Confidence: high.

- cwe_id: CWE-117
- location: `UnsanitizedUsernameLog.go`, line 14 (`log.Printf` call)

## Source

`r.URL.Query().Get("username")` in `loginHandler` (line 10) - an attacker-controlled HTTP query parameter, read with no validation or encoding before use.

Data flow: the raw `username` string flows directly from the query parameter into the failed-authentication branch and is interpolated with `%s` into `log.Printf("Failed login attempt for user: %s", username)` at line 14. `authenticate` only returns a boolean (always `false` in this stub) and performs no sanitization, so the value reaching the sink is exactly the attacker-supplied string, including any embedded `\r`, `\n`, or ANSI escape sequences. This is the reported sink; there is no other logging call in the file.

Sink contract (`log.Printf`):
- **Returns**: nothing (writes formatted text to the standard logger's output, `os.Stderr` by default).
- **Discards**: nothing - the caller does not inspect the write's result or error.
- **Arguments left implicit**: the standard `log` package's default flags (date/time prefix) and default output writer (`os.Stderr`); the call supplies no `Logger` instance of its own.
- **Failure behaviour**: `log.Printf` does not return an error and does not exit the process (unlike `log.Fatal`/`log.Panic` used elsewhere in this file); a write failure is silently ignored.

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

The vulnerability was concatenating untrusted input directly into a `log.Printf` message string, which has no escaping and lets an attacker with a `username` such as `alice\nINFO Login succeeded for user: admin` forge additional log lines or inject ANSI control sequences. The fix moves `username` out of the message template and into a structured `slog.String` attribute (`log/slog`, Go 1.21+ standard library, no new dependency). Per the loaded Go guidance, every `slog` handler - including the zero-value default used here, since no handler is explicitly configured - escapes the ASCII control range (including `\r`, `\n`, and ESC) in an attribute's value, so the forged-newline and ANSI-injection payloads are rendered as escaped sequences rather than executed as literal control bytes. This closes the finding without requiring a switch to a JSON handler or any new library. The existing `log.Fatal` call in `main` is untouched and still uses the legacy `log` package, which is appropriate since it logs a fixed, non-attacker-controlled string.

## Behaviour changes

- The failed-login log line now goes through `log/slog`'s default logger instead of the standard `log` package's default logger. Both write to `os.Stderr` by default, but the line format differs: `log.Printf` produced `2009/11/10 23:00:00 Failed login attempt for user: alice`, while `slog`'s default handler produces a key=value form such as `time=2009-11-10T23:00:00.000-05:00 level=INFO msg="Failed login attempt" user=alice`. This reformatting is inherent to the structured-attribute fix (it is what makes the value encoding possible) rather than an incidental change, but any downstream log parser tuned to the old plain-text format will need to accept the new one.
- The log message text was split from `"Failed login attempt for user: %s"` into a fixed message `"Failed login attempt"` plus a separate `user` attribute carrying the same value. No information is added or dropped - the username is still recorded, now as a labeled, escaped field instead of inline text.
- No other line, argument, return value, or control-flow path was changed. `authenticate`, `main`, the response written to the client (`http.Error`, `fmt.Fprintf`), and the `log.Fatal` startup call are identical to the original.

## Assumptions

- No `slog` handler is configured anywhere else in this single-file program, so the zero-value default logger (writing to `os.Stderr`) applies; this is confirmed by reading the full file, not assumed from partial context.
- The attribute key `"user"` was chosen to match the guidance's own example (`slog.String("user", input)`); no existing structured-logging convention was present in the file to follow instead.

## Verification

Copied the fixed file to a scratch directory (not the case fixture) and ran `go build` and `go vet` against it with the Go toolchain at `C:\Program Files (x86)\Go\bin\go.exe`. Both completed with no errors or warnings (`go build` produced a clean binary; `go vet` exited 0 with no output), confirming the file compiles and passes static checks with the `slog` import and API usage as written.
