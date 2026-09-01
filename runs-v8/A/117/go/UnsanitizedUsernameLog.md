## Verdict
CWE-117: Improper Output Neutralization for Logs confirmed. Unsanitized user input from URL query parameter is passed directly to log output, allowing log injection/spoofing attacks through control characters.

## Source
The `username` parameter is obtained from the HTTP request URL query string at line 10:
```go
username := r.URL.Query().Get("username")
```

This untrusted, user-controlled input flows directly into the log statement at line 14 without any sanitization.

## Fix
Replace line 14 with:

```go
log.Printf("Failed login attempt for user: %s", strings.TrimSpace(strings.ReplaceAll(username, "\n", " ")))
```

Or, more comprehensively, sanitize all common control characters:

```go
sanitized := strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(username)
log.Printf("Failed login attempt for user: %s", sanitized)
```

Alternatively, import `strings` and trim the input before logging:

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
		// Sanitize username to remove control characters that could be used for log injection
		sanitized := strings.ReplaceAll(strings.ReplaceAll(username, "\n", ""), "\r", "")
		log.Printf("Failed login attempt for user: %s", sanitized)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "welcome, %s", username)
}
```

## Explanation
Attackers can inject newlines (`\n`) or carriage returns (`\r`) into the username parameter to create forged log entries, making it appear that authorized actions occurred when they did not. For example, `username=attacker%0ASuccessful%20login%20for%20user:%20admin` would produce:
```
Failed login attempt for user: attacker
Successful login for user: admin
```

The fix removes or replaces control characters (newlines, carriage returns, and optionally tabs) with safe alternatives before logging. This prevents the attacker from breaking out of the intended log line and injecting false entries. The `strings.ReplaceAll()` function is a standard Go approach for this sanitization.
