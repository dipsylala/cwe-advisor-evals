## Verdict

Confirmed. The `file` query parameter is attacker-controlled and is joined directly onto `docsRoot` with no traversal check before being passed to `os.ReadFile`, so a value such as `../../../../etc/passwd` (or an absolute path, which `filepath.Join` also passes through once cleaned) lets a client read any file the process can access, outside `/var/app/docs`.

## Source

`name := r.URL.Query().Get("file")` on line 12 (`net/http` request query parameter `file`) in `downloadHandler`.

## Fix

```go
package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const docsRoot = "/var/app/docs"

func resolveDocPath(name string) (string, error) {
	// Reject empty input and any path separator or traversal segment up front.
	if name == "" || strings.ContainsAny(name, `/\`) || name == ".." {
		return "", errors.New("invalid file name")
	}

	joined := filepath.Join(docsRoot, name)

	// Belt-and-braces: confirm the cleaned, resolved path still lives under docsRoot.
	rel, err := filepath.Rel(docsRoot, joined)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("invalid file name")
	}

	return joined, nil
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	if name == "" {
		http.Error(w, "missing file parameter", http.StatusBadRequest)
		return
	}

	path, err := resolveDocPath(name)
	if err != nil {
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

`filepath.Join` only lexically cleans the resulting path (collapsing `..` segments algebraically); it does not confine the result to `docsRoot`. Because `name` is taken verbatim from the URL query string, a request like `?file=../../../../etc/passwd` produces a joined path that walks back out of `docsRoot` before `os.ReadFile` opens it, and an absolute-looking value can be manipulated similarly since `Join` treats every element as a plain path segment rather than validating it against a root.

The fix applies two layers of defense:

1. **Reject structure, not just content.** Since legitimate downloads are expected to be single file names (not nested paths), rejecting any input containing `/` or `\`, or equal to `..`, removes the primary traversal vector before any path math happens. This also blocks Windows-style separators, which `filepath.Join`/`Clean` on a Unix deployment would otherwise pass through as literal (non-normalized) characters that some downstream filesystem or library could still interpret specially.
2. **Verify containment after joining.** `filepath.Rel(docsRoot, joined)` computes the relative path from the trusted root to the resolved target. If that relative path is `..` or starts with `../`, the resolved file lies outside `docsRoot` and the request is rejected. This catches any traversal sequence the first check might miss (for example, encoded or unusual segment combinations) and keeps the containment check anchored to the actual filesystem path rather than to string patterns alone.

Together these ensure `os.ReadFile` only ever receives a path that both originates as a plain, separator-free file name and resolves to a location inside the intended `docsRoot` directory.
