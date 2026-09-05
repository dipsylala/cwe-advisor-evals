## Verdict

CWE-209 confirmed. Line 16 passes the full error chain directly to the client via `http.Error(w, wrapped.Error(), ...)`, exposing file system paths and OS-level error details (e.g., file not found, permission denied) that reveal application internals to an attacker.

## Source

The vulnerability originates in the error handling path:
1. `os.Open("/var/data/reports/" + filename)` (line 12) produces an error containing system details
2. `fmt.Errorf("could not open report %q: %w", filename, err)` (line 14) wraps the error, preserving the original message and including the requested filename
3. `http.Error(w, wrapped.Error(), http.StatusInternalServerError)` (line 16) sends the full error message to the client - this is the sink

## Fix

```go
func downloadHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")

	f, err := os.Open("/var/data/reports/" + filename)
	if err != nil {
		// Log detailed error server-side for debugging
		log.Printf("Failed to open report: filename=%q error=%v", filename, err)
		// Return generic message to client
		http.Error(w, "An error occurred while retrieving the report", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	fmt.Fprintf(w, "serving report %s", filename)
}
```

Replace the error handling block (lines 13-17) with server-side logging and a generic client response. The `log.Printf()` call captures the full error details for operational debugging, while the HTTP response returns only a fixed, user-facing message that does not expose file paths, OS error codes, or system configuration.

## Explanation

The fix separates internal diagnostic information from client-facing error messages. The original code sent `err.Error()` directly to clients, which for file operations typically includes paths ("open /var/data/reports/secret.txt: permission denied") and system details. The remediation logs the detailed error server-side where it can inform debugging and incident response, but returns a generic message to the client. This prevents information disclosure without sacrificing observability - operations teams still see the full error in logs, but external attackers do not learn about the application's file structure, permissions model, or dependencies.

## Behaviour changes

- **Client-facing error message**: Changes from detailed (e.g., "could not open report \"../../etc/passwd\": open /var/data/reports/../../etc/passwd: permission denied") to generic ("An error occurred while retrieving the report")
- **Logging**: Adds server-side structured logging with filename and error details for debugging and monitoring
- **HTTP status code**: Remains 500 (no change)
- **Response format**: Remains plain text error via `http.Error()` (no change)
- **Functional impact**: None - the application still rejects invalid file requests and serves reports normally; only the error message surface has changed
