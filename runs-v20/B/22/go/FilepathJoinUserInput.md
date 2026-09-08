## Verdict

Confirmed. `downloadHandler` builds a filesystem path from an unvalidated query parameter and passes it to `os.ReadFile` with no containment check, allowing traversal outside `docsRoot`.

## Source

`r.URL.Query().Get("file")` in `downloadHandler` (`FilepathJoinUserInput.go:12`) - fully attacker-controlled via the `file` query parameter, only checked for emptiness.

## Fix

Data flow: `name` (query param) -> `filepath.Join(docsRoot, name)` (line 18) -> `os.ReadFile(path)` (line 21, the reported sink). `filepath.Join` normalizes syntax (resolves `.`/`..`) but performs no containment check, so `name = "../../etc/passwd"` cleans to a path outside `docsRoot` and is read as-is. No validation of any kind occurs between source and sink.

Sink contract for `os.ReadFile`: returns `([]byte, error)`; the caller writes the bytes verbatim to the response and maps any error to a generic 404 `"not found"`, discarding the underlying error detail (already the case, preserved). No other arguments are implicit. The fix must preserve this same success/failure shape.

### File: FilepathJoinUserInput.go
```go
package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const docsRoot = "/var/app/docs"

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	if name == "" {
		http.Error(w, "missing file parameter", http.StatusBadRequest)
		return
	}

	base, err := filepath.Abs(docsRoot)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	path := filepath.Join(base, name)
	if path != base && !strings.HasPrefix(path, base+string(filepath.Separator)) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}
```

## Explanation

`filepath.Join` already calls `filepath.Clean` internally, which collapses `..` segments syntactically but never checks that the result stays under `docsRoot` - it is normalization, not a security boundary (per the Go-specific guidance). The fix makes `docsRoot` absolute with `filepath.Abs` (defensive; it is already an absolute literal here) and, after the join, verifies the resulting path either equals that base or has it as a proper prefix using `strings.HasPrefix(path, base+string(filepath.Separator))`. The explicit separator is required so a sibling directory that merely shares the prefix (e.g. `/var/app/docs-secret`) cannot pass, and the `path != base` clause preserves access to the base directory itself. Only the already-joined, already-checked `path` variable is used for the file read - the raw `name` value never reaches `os.ReadFile` directly. This closes the traversal without adding a redundant raw `..` substring test, consistent with the guidance's canonicalize-then-contain approach.

Verification performed: the fixed file was copied to a scratch Go module (`go 1.21`, well below the installed 1.25.5 toolchain) and checked with `go vet ./...`, which completed cleanly (no diagnostics). Both new imports (`strings`, already-present `path/filepath`) are standard library. `filepath.Abs`, `filepath.Join`, `filepath.Separator`, and `strings.HasPrefix` are all standard-library functions used with their documented signatures.

## Behaviour changes

- A `file` value that resolves (after join) outside `docsRoot` now returns `404 "not found"` instead of leaking the requested file's contents - this is the intended close of the vulnerability, not a regression.
- A `file` value that resolves inside `docsRoot`, including one that legitimately contains `..` as a substring (e.g. `notes..v2.txt`) or uses redundant `./` segments, continues to be served exactly as before.
- No change to response headers, content type, or the error message/status used for "not found" vs "bad request" - the existing error-handling contract is preserved.
