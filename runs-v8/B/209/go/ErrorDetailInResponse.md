## Verdict

Confirmed. `http.Error(w, wrapped.Error(), http.StatusInternalServerError)` at line 16 sends a detailed error message to the client that exposes the filesystem path and OS-level error details. This leaks sensitive information about the application's internal structure.

## Source

The vulnerability occurs in the error handler at line 12-16. The `os.Open()` call fails with a filesystem error, which is then wrapped with additional context (including the user-supplied filename) at line 14, and finally serialized into the HTTP response body via `http.Error()` at line 16. The wrapped error message contains:

- Filesystem path structure (`/var/data/reports/`)
- OS error details (e.g., "permission denied", "no such file or directory")
- The requested filename from the query parameter

All of this is information an attacker can use to map the application's internal file organization and infer permission model details.

## Fix

Replace the vulnerable error handling with a pattern that logs the full error server-side and returns only a generic message to the client:

```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")

	f, err := os.Open("/var/data/reports/" + filename)
	if err != nil {
		// Log detailed error server-side for debugging
		log.Printf("Failed to open report file: %v", err)
		// Return only a generic error message to the client
		http.Error(w, "An error occurred while processing your request", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	fmt.Fprintf(w, "serving report %s", filename)
}

func main() {
	http.HandleFunc("/download", downloadHandler)
	http.ListenAndServe(":8080", nil)
}
```

The key change is at line 16 (formerly): replace `http.Error(w, wrapped.Error(), ...)` with `http.Error(w, "An error occurred while processing your request", ...)`. The full error details are logged server-side via `log.Printf()` instead.

## Explanation

The Go error-handling convention of returning error values often leads to developers serializing raw errors directly into HTTP responses via `http.Error(w, err.Error(), ...)`. This exposes internal details such as filesystem paths, database driver messages, and OS error codes to clients.

The fix separates the internal error (logged server-side with full context for debugging) from a fixed, generic user-facing message sent to clients. The client receives only "An error occurred while processing your request", which describes the caller's situation without revealing the application's internal structure, file paths, or error classification.

This pattern follows CWE-209 remediation guidance: suppress exception details, driver names, and vendor error codes in client-facing messages, while preserving them in server-side logs for monitoring and debugging.

## Behaviour changes

**Client-visible changes:**
- HTTP error response body changes from `"could not open report "X": open /var/data/reports/X: no such file or directory"` to `"An error occurred while processing your request"`
- HTTP status code remains `500`

**Server-side changes:**
- Application logs now include detailed error information via `log.Printf()`, which was not logged before
- Developers can debug filesystem errors using server logs instead of relying on error responses

**Security impact:**
- Error response no longer leaks filesystem paths, permission model details, or OS error codes
- Attack surface for internal structure enumeration is reduced
