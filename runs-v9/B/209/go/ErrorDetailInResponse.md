## Verdict

Exploitable. `filename` comes from the request query string (`r.URL.Query().Get("file")`), and when `os.Open` fails, the resulting `error` - which for a Go `*PathError` includes the full filesystem path `/var/data/reports/<filename>` plus the OS-level failure reason - is wrapped and written straight into the HTTP response via `http.Error(w, wrapped.Error(), ...)`. Any request that causes the open to fail (missing file, permission error, or a path-traversal attempt) discloses the server's internal directory layout to the client.

## Source

`r.URL.Query().Get("file")` in `downloadHandler` (line 10), flowing unmodified into the file path built at line 12 and, on failure, into the wrapped error at line 14.

## Fix

Vulnerable code:

```go
f, err := os.Open("/var/data/reports/" + filename)
if err != nil {
    wrapped := fmt.Errorf("could not open report %q: %w", filename, err)
    // SAST FINDING: CWE-209 (Generation of Error Message Containing Sensitive Information) reported here. Sink is the next statement.
    http.Error(w, wrapped.Error(), http.StatusInternalServerError)
    return
}
```

Fixed code:

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
		slog.Error("could not open report", "file", filename, "error", err)
		http.Error(w, "could not open report", http.StatusInternalServerError)
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

The handler previously sent `wrapped.Error()` - which embeds the full server-side path and the raw OS error text - directly to the client through `http.Error`. The fix splits the two audiences the original code conflated: the detailed error (including the requested filename and the underlying `os.PathError`) is now logged server-side with `slog.Error` and structured fields for later debugging, while the client receives only a fixed, generic message, `"could not open report"`. The HTTP status code is left unchanged, so callers that already branch on 500 still work; only the response body's content changes, which is the only thing carrying the sensitive detail.

## Behaviour changes

- Response body on open failure changed from `could not open report "<filename>": open /var/data/reports/<filename>: <os error>` to the fixed string `could not open report`. This is the fix itself - the removed text is exactly the internal path and OS-level detail the finding flags.
- The previously-discarded detailed error is now written to server-side logs via `slog.Error` (file name, and the underlying error) instead of being silently dropped after `http.Error` returned - this is additive observability, not a leak, since it is never sent to the client.
- Status code (`http.StatusInternalServerError`), success-path behavior, and all other handler logic are unchanged.
