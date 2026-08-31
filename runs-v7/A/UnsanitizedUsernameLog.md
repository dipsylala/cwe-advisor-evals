## Verdict

Confirmed. The username parameter is passed directly to `log.Printf()` without sanitization, allowing log injection via newline characters.

## Source

Line 10: `username := r.URL.Query().Get("username")` — untrusted input from URL query parameter.

## Fix

Sanitize the username by stripping or replacing newline and carriage return characters before logging:

```go
import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	if !authenticate(username) {
		// Sanitize username before logging by removing newlines and carriage returns
		sanitizedUsername := strings.NewReplacer("\n", "", "\r", "").Replace(username)
		log.Printf("Failed login attempt for user: %s", sanitizedUsername)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "welcome, %s", username)
}
```

Alternatively, use structured logging which escapes problematic characters automatically.

## Explanation

Log injection occurs when untrusted input reaches a log sink without neutralization. A malicious username like `attacker\nSuccessfully logged in as admin` creates a fake log entry by injecting a newline, deceiving log analysis and audit trails. Stripping `\n` and `\r` characters before logging prevents the attacker from breaking into new log lines. The `username` variable used in the HTTP response (line 19) can remain unsanitized for that context, as it is HTML-encoded by `http.ResponseWriter`.
