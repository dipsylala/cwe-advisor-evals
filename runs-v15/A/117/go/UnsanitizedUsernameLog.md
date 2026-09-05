## Verdict

This is a genuine CWE-117 finding. The username parameter from the URL query is logged directly without sanitization, allowing log injection attacks where an attacker can inject newline characters to manipulate log output and potentially conceal malicious activity.

## Source

Line 14 in `loginHandler`:
```go
log.Printf("Failed login attempt for user: %s", username)
```

The `username` variable is populated from untrusted user input (`r.URL.Query().Get("username")`) and passed directly to the log sink without any sanitization.

## Fix

Sanitize the username by removing or replacing problematic characters before logging:

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
		// Sanitize username by removing newlines and carriage returns
		sanitized := strings.NewReplacer("\n", "", "\r", "").Replace(username)
		log.Printf("Failed login attempt for user: %s", sanitized)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "welcome, %s", username)
}
```

## Explanation

Log injection occurs when untrusted input containing newline characters is written to logs, allowing attackers to inject fake log entries. This can be used to hide traces of malicious activity, inject false error messages, or create log entries that appear to be legitimate system events.

The fix uses `strings.NewReplacer` to remove newline (`\n`) and carriage return (`\r`) characters from the username before logging. This ensures that user input cannot break out of the current log line and inject arbitrary content. The replacement approach is preferred over stripping because it keeps the log entry on a single line while preserving the sanitized username for auditing purposes.

Note: The username is still used unsanitized in the response on line 19, but that is outside the scope of this CWE-117 finding which focuses on log output neutralization specifically.
