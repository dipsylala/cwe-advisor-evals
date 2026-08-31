## Verdict

Confirmed. `downloadHandler` builds a filesystem path from an unvalidated query parameter and reads it directly, allowing path traversal outside `docsRoot`.

## Source

`name := r.URL.Query().Get("file")` (line 12) - the `file` query parameter is fully attacker-controlled and reaches `os.ReadFile` (line 21) with no validation, sanitization, or containment check in between. `filepath.Join(docsRoot, name)` (line 18) calls `filepath.Clean` internally, which collapses `..` segments arithmetically but does not stop the result from resolving above `docsRoot` - a request such as `?file=../../../../etc/passwd` produces a joined path outside the intended directory, and `os.ReadFile` will happily read it.

## Fix

Reject traversal segments and verify the resolved path is still contained within `docsRoot` before opening it:

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

	// Reject path separators and traversal outright - only bare filenames
	// are valid input for this handler.
	if strings.ContainsAny(name, `/\`) || name == ".." {
		http.Error(w, "invalid file parameter", http.StatusBadRequest)
		return
	}

	path := filepath.Join(docsRoot, name)

	// Defense in depth: confirm the resolved path still lives under docsRoot
	// before touching the filesystem.
	rel, err := filepath.Rel(docsRoot, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		http.Error(w, "invalid file parameter", http.StatusBadRequest)
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

The root cause is that `filepath.Join` is a path-arithmetic function, not a security boundary: it normalizes `..` segments syntactically but is perfectly willing to produce a result outside `docsRoot` when the input contains enough `../` sequences (or an absolute path override on some platforms). Relying on it alone to "contain" user input is the classic mistake behind this class of bug.

The fix applies two independent layers:

1. **Reject structure, not just traversal tokens.** Refusing any input containing a path separator (`/` or `\`) or the literal `..` component means the handler only ever accepts a bare filename, which is all the endpoint's stated purpose requires. This is stronger than a naive substring blocklist for `../` because it also stops absolute paths, mixed separators, and encoded traversal that a Join-then-blocklist approach might miss.
2. **Verify containment after resolution, not just before.** Computing `filepath.Rel(docsRoot, path)` and checking the result doesn't start with `..` catches any residual escape the first check didn't anticipate (defense in depth), and is the standard idiomatic way to confirm one path is truly nested inside another in Go, since there is no built-in "is-subpath" check in `path/filepath`.

Together these ensure `os.ReadFile` only ever receives a path that resolves to a file directly inside `docsRoot`, closing the traversal while preserving the handler's existing behavior for legitimate filenames.
