## Verdict
Confirmed. Unsanitized user input from `r.URL.Query().Get("username")` is logged directly, allowing log injection attacks via newlines and control characters.

## Source
Line 10 receives untrusted `username` from the URL query string:
```
username := r.URL.Query().Get("username")
```

## Fix
Replace line 14 with sanitized output that strips or escapes newlines and other whitespace control characters:

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
		sanitizedUsername := strings.ReplaceAll(username, "\n", " ")
		sanitizedUsername = strings.ReplaceAll(sanitizedUsername, "\r", " ")
		log.Printf("Failed login attempt for user: %s", sanitizedUsername)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "welcome, %s", username)
}
```

Alternatively, use structured logging with `log/slog` (Go 1.21+) to separate metadata from strings:

```go
import (
	"log/slog"
	"net/http"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	if !authenticate(username) {
		slog.Warn("failed login attempt", "user", username)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "welcome, %s", username)
}
```

## Explanation
CWE-117 occurs when user-controlled data is written to logs without sanitization. Attackers can inject newline characters (`\n` or `\r\n`) to create fake log entries, manipulate log analysis tools, or hide malicious activity. 

The username is untrusted because it comes from a URL query parameter. Removing or replacing control characters before logging prevents injection. Structured logging (with `slog`) is the preferred modern approach because it treats user data as a field value rather than text, making injection impossible regardless of content.
