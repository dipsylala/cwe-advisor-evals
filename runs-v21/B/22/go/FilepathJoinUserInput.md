## Verdict

CWE-22 path traversal confirmed. The `name` query parameter reaches `filepath.Join` unchecked, allowing attackers to provide `../` sequences that escape the intended `/var/app/docs` directory and read arbitrary files.

## Source

File: `FilepathJoinUserInput.go`, line 12. The untrusted `name` parameter from `r.URL.Query().Get("file")` is used directly in path construction at line 18 without validation, then passed to `os.ReadFile()` at line 21.

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

	// Reject absolute paths to prevent escaping the root
	if filepath.IsAbs(name) {
		http.Error(w, "invalid file path", http.StatusBadRequest)
		return
	}

	// Make the base directory absolute for canonical comparison
	absRoot, err := filepath.Abs(docsRoot)
	if err != nil {
		http.Error(w, "invalid base path", http.StatusInternalServerError)
		return
	}

	// Join the base with the requested name and canonicalize
	path := filepath.Join(absRoot, name)
	absPath, err := filepath.Abs(path)
	if err != nil {
		http.Error(w, "invalid file path", http.StatusBadRequest)
		return
	}

	// Enforce containment: the resolved path must be within or equal to the base directory
	if absPath != absRoot && !strings.HasPrefix(absPath, absRoot+string(filepath.Separator)) {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	// Use only the validated canonical path for the file operation
	data, err := os.ReadFile(absPath)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}
```

## Explanation

The fix closes the path traversal by enforcing canonicalization and containment before accessing the filesystem. First, absolute paths are rejected outright—`filepath.IsAbs(name)` catches attempts like `/etc/passwd`. Next, both the base directory and the joined path are converted to absolute canonical form using `filepath.Abs()`, which resolves `.` and `..` sequences and symlinks relative to the working directory. The containment check then verifies that the resolved absolute path either equals the base directory or begins with the base directory followed by a path separator. The separator requirement is critical: without it, a sibling directory like `/var/app/docs-other` would incorrectly pass a string-prefix test against `/var/app/docs`. Only after this validation passes does the code use the validated canonical path (`absPath`) for the `os.ReadFile()` call, ensuring the tainted original `name` cannot influence the actual filesystem operation.

## Behaviour changes

- Requests with absolute paths (e.g., `?file=/etc/passwd`) are now rejected with HTTP 400 Bad Request.
- Requests with path traversal sequences (e.g., `?file=../../etc/passwd`) that resolve outside the base directory are now rejected with HTTP 403 Forbidden.
- Requests for files legitimately within `/var/app/docs` are unaffected and continue to return the file content with HTTP 200.
- A new internal error response (HTTP 500) is possible if `filepath.Abs()` fails on the base directory, which is unlikely in normal operation.
