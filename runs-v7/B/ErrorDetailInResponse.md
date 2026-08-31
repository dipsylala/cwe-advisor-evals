## Verdict

exploitable

## Source

The error originates from `os.Open()` on line 12, called with a path constructed from user-controlled input (`filename`). The error returned by `os.Open()` contains system-level details such as file paths, permission errors, or "file not found" messages. This error is wrapped into a new error message via `fmt.Errorf()` on line 14, which preserves the original error text using the `%w` verb. The wrapped error is then directly serialized to the HTTP response via `http.Error(w, wrapped.Error(), ...)` on line 16, exposing the sensitive details to the client.

## Fix

**Vulnerable code (lines 13-17):**
```go
if err != nil {
	wrapped := fmt.Errorf("could not open report %q: %w", filename, err)
	// SAST FINDING: CWE-209 (Generation of Error Message Containing Sensitive Information) reported here. Sink is the next statement.
	http.Error(w, wrapped.Error(), http.StatusInternalServerError)
	return
}
```

**Fixed code:**
```go
if err != nil {
	log.Printf("Failed to open report %q: %v", filename, err)
	http.Error(w, "Failed to open report", http.StatusInternalServerError)
	return
}
```

Note: Add `"log"` to the import block if not already present.

## Explanation

The fix separates the internal error (logged server-side) from the generic message returned to the client. The detailed error message from `os.Open()`, which may include file paths and system details, is now logged via `log.Printf()` with full context for server-side debugging and monitoring. The client receives only the fixed generic message "Failed to open report", revealing nothing about the application's internal structure or why the operation failed. This eliminates the information leak while preserving the ability to debug the issue through server logs.

## Behaviour changes

- Added server-side logging: the detailed error with filename context is now recorded via `log.Printf()` before the response is sent. Reason: CWE-209 remediation requires logging detailed errors internally while exposing only generic messages to clients.
- Changed HTTP response body: from a wrapped error message (e.g., "could not open report "test": open /var/data/reports/test: no such file or directory") to a fixed constant message ("Failed to open report"). Reason: prevents exposure of file paths and system error details to the client.
- HTTP status code remains `http.StatusInternalServerError` (500): no change.
- No change to handler flow, return behavior, or subsequent file operations.
