## Verdict

Confirmed. The `username` value comes from the unauthenticated request query string (`r.URL.Query().Get("username")`) and is written into the application log via `log.Printf` with no neutralization. An attacker can submit a `username` value containing `\r` or `\n` (and other control/format characters) to inject fabricated log lines or corrupt the structure of the log, enabling log forging and hindering downstream log parsing/SIEM analysis.

## Source

`E:/Github/cwe-advisor/evals/cases/117/go/UnsanitizedUsernameLog/UnsanitizedUsernameLog.go`, line 10:

```go
username := r.URL.Query().Get("username")
```

This value flows unmodified into the sink at line 14:

```go
log.Printf("Failed login attempt for user: %s", username)
```

## Fix

### File: UnsanitizedUsernameLog.go

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
		// Use %q instead of %s: it quotes the value and escapes control
		// characters (CR, LF, tab, etc.), so attacker-controlled input
		// cannot inject newlines or forge additional log lines.
		log.Printf("Failed login attempt for user: %q", username)
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

The only change is the log format verb at the sink: `%s` became `%q`. Go's `fmt`/`log` package implements `%q` by producing a double-quoted Go string literal, escaping any character that is not a printable, unambiguous rune — including `\r`, `\n`, and other control characters — using backslash escapes (e.g. a submitted value of `admin\r\nINFO: fake entry` renders as `"admin\r\nINFO: fake entry"` on a single log line, with the escape sequences visible as literal text rather than acting as line terminators). This closes the log injection/forging vector without discarding or altering the legitimate username data, and every log line for this event keeps a single, parseable structure. The change is confined to the logging call; the value returned to the HTTP response at line 19 is unrelated to the log-injection finding and is left as-is.
