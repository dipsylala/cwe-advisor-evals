## Verdict

Exploitable

## Source

User-supplied query parameter `file` from `r.URL.Query().Get("file")` at line 12.

## Fix

**Vulnerable Code:**
```go
func downloadHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	if name == "" {
		http.Error(w, "missing file parameter", http.StatusBadRequest)
		return
	}

	path := filepath.Join(docsRoot, name)

	// SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}
```

**Fixed Code:**
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

	// Reject absolute paths and parent directory traversal attempts
	if filepath.IsAbs(name) || strings.HasPrefix(name, "..") {
		http.Error(w, "invalid file parameter", http.StatusBadRequest)
		return
	}

	// Join and canonicalize the path
	path := filepath.Join(docsRoot, name)
	path = filepath.Clean(path)

	// Verify the resolved path is contained within docsRoot
	if path != docsRoot && !strings.HasPrefix(path, docsRoot+string(filepath.Separator)) {
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

The original code constructs a file path by joining a user-supplied filename with a base directory using `filepath.Join`, but performs no validation to ensure the resulting path stays within the intended directory. This allows path traversal attacks: an attacker can pass `?file=../../../etc/passwd` which, after joining with `/var/app/docs`, resolves to `/etc/passwd`, bypassing the intended containment.

The fix adds three layers of protection. First, it rejects inputs that are absolute paths (checked with `filepath.IsAbs`) or start with `..`, preventing obvious traversal attempts. Second, it canonicalizes the joined path with `filepath.Clean` to normalize relative references. Third, and most importantly, it enforces directory containment after canonicalization by verifying the resolved path either equals the base directory or is a proper child of it (checked with `strings.HasPrefix` plus the separator to avoid sibling directory bypasses like `/app/uploads-secret` matching `/app/uploads`). Only paths that pass this boundary check reach `os.ReadFile`.

## Behaviour changes

**Added import:** `"strings"` package is now imported to support the `HasPrefix` comparison.

**Added validation:** Input validation rejects absolute paths and traversal attempts before path construction. This causes invalid requests to return a 400 Bad Request status instead of attempting file access.

**Added containment check:** After path construction and canonicalization, a boundary check verifies the resolved path is contained within the base directory. Paths outside the boundary return 404 Not Found instead of attempting file access.

**No change to success case:** Valid filenames within the intended directory are processed identically - the file is read and served with the same content type and response structure as before.
