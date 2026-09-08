## Verdict

Exploitable. CWE-209 (Generation of Error Message Containing Sensitive Information).

## Source

`r.URL.Query().Get("file")` (line 10) - the attacker-controlled `file` query parameter, read into `filename`.

## Fix

### File: ErrorDetailInResponse.go

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
		slog.Error("could not open report", "filename", filename, "error", err)
		http.Error(w, "Request failed", http.StatusInternalServerError)
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

`filename` flows unvalidated from the query string into `os.Open`, and on failure the resulting `*fs.PathError` (its `Error()` text includes the full filesystem path `/var/data/reports/<filename>` plus the OS-level failure reason, e.g. "no such file or directory" or "permission denied") is wrapped with `fmt.Errorf("...: %w", err)` and passed straight into `http.Error(w, wrapped.Error(), ...)` at the sink on line 16. `fmt.Errorf`'s `%w` preserves the wrapped error for `errors.Is`/`errors.As` but does not sanitize its text, so the client receives the server's internal directory layout and the raw OS error string. The fix keeps the same open call, status code, and control flow, but stops building a client-facing message from `err`/`wrapped` at all: the full error (with the filename as a structured field) is logged server-side via `log/slog`, and the client response is replaced with the fixed, generic string `"Request failed"` written through the same `http.Error` call. This satisfies the sink's existing contract (same `ResponseWriter`, same `http.StatusInternalServerError`, same early return) while removing every piece of caller-visible internal detail.

## Behaviour changes

- Response body on the error path changes from `could not open report "<filename>": open /var/data/reports/<filename>: <os error>` to the fixed string `Request failed` - intentional; this is the weakness being closed.
- The detailed error (previously discarded - not logged anywhere) is now written server-side via `slog.Error` with structured fields (`filename`, `error`). This is an addition of server-side diagnostics, not a new leak, and preserves the ability to debug the failure that the original code discarded.
- HTTP status code remains `http.StatusInternalServerError` (500) - unchanged, since the code cannot reliably distinguish "file not found" from other `os.Open` failures (e.g. permission errors) without additional checks, and changing status semantics was out of scope for this finding.
- No change to the success path (line 21-22): the response still echoes `filename` in `Fprintf(w, "serving report %s", filename)`. This is outside the CWE-209 finding at line 16 (it is not an error message and carries no internal/system detail - it echoes back the same value the client supplied) and was left untouched to keep the fix scoped to the reported sink.

## Verification

`go vet ./...` and `go build ./...` were run against the fixed file in an isolated scratch module (Go 1.25.5 toolchain, `go mod init` then vet/build) - both completed with no output/errors, confirming the file compiles and passes static analysis. `log/slog` is part of the Go standard library since Go 1.21, so no new dependency was introduced.
