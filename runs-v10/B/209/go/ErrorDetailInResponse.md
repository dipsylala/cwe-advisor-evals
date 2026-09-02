## Verdict

Exploitable. The error message constructed at line 14 is directly sent to the HTTP client at line 16 via `http.Error()`, exposing both the filename query parameter and the underlying OS error details (such as "no such file or directory").

## Source

The attacker-controlled filename originates from the query parameter at line 10:
```
filename := r.URL.Query().Get("file")
```

This value flows into the file path at line 12 (`"/var/data/reports/" + filename`), and when `os.Open()` fails, the error message leaks this context back to the client.

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
    // Log full error details server-side for debugging
    log.Default().Error("failed to open report",
        "error", err,
        "filename", filename,
    )
    // Return only a generic error message to the client
    http.Error(w, "An error occurred while processing your request", http.StatusInternalServerError)
    return
}
```

**Required import addition:**
Add `"log"` to the imports at the top of the file (it is part of the Go standard library and does not require installation).

## Explanation

The fix separates internal diagnostic information from the user-facing error response. The detailed error—including the filename and OS-level error message—is logged server-side using Go's standard `log` package, where it can be used for debugging and monitoring. The client receives only a generic, non-descriptive message that does not expose information about the application's file structure, configuration, or internal error handling. This prevents attackers from using error messages to enumerate directories, infer the application's architecture, or gather reconnaissance information.

## Behaviour changes

- **Added import:** `"log"` is added to the imports. This is a standard library package with no external dependency.
- **Logging introduced:** A call to `log.Default().Error()` is inserted before the HTTP response, recording the full error and filename server-side. This replaces the implicit loss of detailed error information and enables operational visibility.
- **HTTP response message changed:** The `http.Error()` call now sends a static, generic message ("An error occurred while processing your request") instead of `wrapped.Error()`. The status code remains `http.StatusInternalServerError` (500).
- **No change to success path:** The handler's success path (line 22) and other behavior remain unchanged.
