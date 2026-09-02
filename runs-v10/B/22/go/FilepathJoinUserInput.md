## Verdict

Exploitable path traversal vulnerability. User input reaches the file operation without validation, allowing traversal outside the intended base directory.

## Source

Line 12: `name := r.URL.Query().Get("file")` — untrusted HTTP query parameter passed directly to path construction at line 18.

## Fix

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

	// Reject absolute paths and traversal sequences
	if filepath.IsAbs(name) || strings.Contains(name, "..") {
		http.Error(w, "invalid file parameter", http.StatusBadRequest)
		return
	}

	// Make base absolute
	base, _ := filepath.Abs(docsRoot)
	
	// Join and normalize the path
	path := filepath.Join(base, name)
	path = filepath.Clean(path)

	// Verify the path is contained within the base directory
	if path != base && !strings.HasPrefix(path, base+string(filepath.Separator)) {
		http.Error(w, "access denied", http.StatusForbidden)
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

The fix adds validation at three points:

1. **Reject traversal syntax** (lines 17–20): Reject inputs containing `..` or absolute paths before any path operations. These are guaranteed escapes.

2. **Canonicalize against an absolute base** (lines 22–26): Convert the base directory to absolute form with `filepath.Abs`, then join and clean the resulting path. `filepath.Clean` resolves `.` and `..` sequences; joining against an absolute base ensures the result is also absolute.

3. **Verify containment** (lines 28–30): After canonicalization, check that the resolved path either equals the base directory or starts with `base + /`. The separator is critical—without it, `/var/app/uploads-secret` would pass a prefix check against `/var/app/uploads`. The equality case permits reading the base directory itself if needed.

Only the validated path is then passed to `os.ReadFile`, ensuring the file operation cannot reach outside the intended directory.

## Behaviour changes

- Requests with absolute paths (e.g., `file=/etc/passwd`) are now rejected with HTTP 400 Bad Request.
- Requests with traversal sequences (e.g., `file=../../../etc/passwd`) are rejected with HTTP 400 Bad Request.
- Requests targeting files outside the base directory (e.g., after resolving symlinks or edge cases not caught by syntax checks) are rejected with HTTP 403 Forbidden.
- Valid relative paths within the base directory (e.g., `file=document.pdf`, `file=subdir/file.txt`) continue to work as before.
