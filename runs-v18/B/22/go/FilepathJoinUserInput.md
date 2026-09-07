## Verdict

Confirmed path traversal vulnerability. User input from query parameter reaches os.ReadFile without containment validation.

## Source

- Line 12: `name := r.URL.Query().Get("file")` — untrusted query parameter (source)
- Line 18: `path := filepath.Join(docsRoot, name)` — path constructed without validation
- Line 21: `os.ReadFile(path)` — sink that reads the file at arbitrary paths

Data flow: untrusted input → filepath.Join → os.ReadFile

## Fix

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

	// Reject absolute paths and inputs starting with ..
	if filepath.IsAbs(name) || strings.HasPrefix(name, "..") {
		http.Error(w, "invalid file parameter", http.StatusBadRequest)
		return
	}

	// Get absolute base directory
	basePath, err := filepath.Abs(docsRoot)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Join and canonicalize the path
	path := filepath.Join(basePath, name)
	resolvedPath := filepath.Clean(path)

	// Verify the resolved path is contained within basePath
	if resolvedPath != basePath && !strings.HasPrefix(resolvedPath, basePath+string(filepath.Separator)) {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	// Read file using the validated path only
	data, err := os.ReadFile(resolvedPath)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}
```

## Explanation

The vulnerability exists because `filepath.Join` normalizes path syntax but does not enforce that the result stays within the base directory. An attacker can use `../` sequences to escape the intended directory.

The fix implements defense-in-depth:

1. **Input validation** (lines 17-19): Reject absolute paths and inputs starting with `..` to catch obvious traversal attempts early.
2. **Absolute base path** (lines 21-25): Convert `docsRoot` to absolute form using `filepath.Abs`; comparing against a relative base would fail to catch sibling-directory escapes.
3. **Path canonicalization** (lines 27-28): Join the absolute base with the validated input, then clean the result to resolve any remaining relative sequences (e.g., `foo/../../bar` becomes `bar`).
4. **Containment check** (lines 30-32): Verify the canonicalized path equals the base directory or starts with base + separator. The separator is critical—a string prefix check alone would incorrectly allow `/app/uploads-secret` to pass a check for `/app/uploads`.
5. **Single trusted variable** (line 35): Use only the validated `resolvedPath` for the file operation, never the original `name`.

This ensures even complex inputs like `foo/../../etc/passwd` cannot escape the base directory.

## Behaviour changes

- Requests with absolute file paths (e.g., `?file=/etc/passwd`) are now rejected with HTTP 400 Bad Request
- Requests with paths starting with `..` (e.g., `?file=../../etc/passwd`) are now rejected with HTTP 400 Bad Request
- Requests with paths that escape the base directory after canonicalization (e.g., `?file=foo/../../etc/passwd`) are now rejected with HTTP 403 Forbidden
- Valid relative file paths within `docsRoot` continue to work normally (e.g., `?file=readme.txt`, `?file=docs/file.pdf`)
- HTTP status codes are more specific: 400 for malformed input, 403 for unauthorized paths, 404 for missing files
