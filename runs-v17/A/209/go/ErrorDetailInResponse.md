## Verdict
CWE-209 confirmed. The error response on line 16 exposes sensitive information (filename and underlying OS error details) to the HTTP client.

## Source
Line 16 sends the detailed error message directly to the HTTP response:
```go
http.Error(w, wrapped.Error(), http.StatusInternalServerError)
```
The `wrapped` error contains both the requested filename and OS-level error details, which could expose sensitive information to an attacker.

## Fix

### File: ErrorDetailInResponse.go
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
		wrapped := fmt.Errorf("could not open report %q: %w", filename, err)
		// Log the detailed error for debugging; send generic message to client
		log.Printf("Error in downloadHandler: %v", wrapped)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
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

## Explanation
The fix separates error handling into two parts:
1. **Internal logging**: The detailed error (containing filename and OS details) is logged server-side using `log.Printf()` for debugging and monitoring.
2. **Client response**: A generic error message ("Internal Server Error") is sent to the HTTP client, preventing exposure of sensitive implementation details.

This approach maintains debuggability while protecting against information disclosure. An attacker cannot infer the file structure, whether specific files exist, or OS-level error conditions from the response alone.
