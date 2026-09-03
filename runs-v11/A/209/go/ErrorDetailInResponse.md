## Verdict
**CONFIRMED** — CWE-209 at line 16. The error message wrapping system-level failure details is directly exposed to the HTTP response.

## Source
```go
wrapped := fmt.Errorf("could not open report %q: %w", filename, err)
http.Error(w, wrapped.Error(), http.StatusInternalServerError)
```

The error includes the filename parameter and the underlying OS error (which may reveal internal directory structure or file permissions). This sensitive information reaches the client in the HTTP response body.

## Fix
Replace the error response with a generic message. Log the detailed error internally for debugging:

```go
func downloadHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")

	f, err := os.Open("/var/data/reports/" + filename)
	if err != nil {
		// Log detailed error for operators, not clients
		log.Printf("failed to open report: %v", err)
		// Return generic error to client
		http.Error(w, "An error occurred while processing your request", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	fmt.Fprintf(w, "serving report %s", filename)
}
```

Alternatively, if the specific failure type needs to be communicated to the client, use a safe representation (e.g., "file not found" for file-not-found errors only, without revealing the path):

```go
if err != nil {
	log.Printf("failed to open report: %v", err)
	if os.IsNotExist(err) {
		http.Error(w, "The requested report was not found", http.StatusNotFound)
	} else {
		http.Error(w, "An error occurred while processing your request", http.StatusInternalServerError)
	}
	return
}
```

## Explanation
CWE-209 occurs when error messages leak sensitive information to untrusted clients. Here, `wrapped.Error()` includes the filename parameter and OS-level error details that reveal internal structure or state. The fix separates concerns: detailed errors are logged server-side for operators to debug; clients receive only a generic, non-revealing message. If certain error types must be communicated (e.g., distinguishing 404 from 500), branch on the error kind rather than exposing the full error text.
