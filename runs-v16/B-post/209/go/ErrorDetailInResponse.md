## Verdict
Exploitable

## Source
The `filename` parameter from `r.URL.Query().Get("file")` at line 10 flows through the error message at line 16 without sanitization.

## Fix

**Vulnerable code:**
```go
func downloadHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")

	f, err := os.Open("/var/data/reports/" + filename)
	if err != nil {
		wrapped := fmt.Errorf("could not open report %q: %w", filename, err)
		// SAST FINDING: CWE-209 (Generation of Error Message Containing Sensitive Information) reported here. Sink is the next statement.
		http.Error(w, wrapped.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	fmt.Fprintf(w, "serving report %s", filename)
}
```

**Fixed code:**
```go
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
)

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")

	f, err := os.Open("/var/data/reports/" + filename)
	if err != nil {
		// Log the full error server-side for debugging
		slog.Error("failed to open report",
			"filename", filename,
			"error", err.Error(),
		)
		// Return a generic message to the client
		http.Error(w, "The requested resource could not be accessed", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	fmt.Fprintf(w, "serving report %s", filename)
}
```

## Explanation

The vulnerable code serializes the raw error from `os.Open()` directly into the HTTP response, exposing internal details such as file paths, the attempted traversal payload, and OS-level error messages to the client. The fix separates concerns: detailed error information including the requested filename and the underlying error (which may contain path separators, file system details, or driver-specific messages) is logged server-side using structured logging with full context, while the client receives only a generic, fixed message that does not describe the application's internals or aid an attacker in reconnaissance. The log entry retains diagnostic information for debugging and monitoring while the HTTP response remains opaque to the client.

## Behaviour changes

**Logging added**: The fix introduces a new server-side log statement via `log/slog`. The original code did not log anything; this is a new addition and not a change to existing behaviour.

**HTTP response body changed**: The original response body was the full error text (e.g., `"could not open report "../../etc/passwd": open /var/data/reports/../../etc/passwd: no such file or directory"`). The fixed response body is a generic static string: `"The requested resource could not be accessed"`. This is intentional - the fix eliminates information leakage by design.

**HTTP status code unchanged**: Both versions return `http.StatusInternalServerError` (500), preserving the error signalling contract.

**No return value or argument changes**: The function signature and return behavior remain identical; only the message content changes.
