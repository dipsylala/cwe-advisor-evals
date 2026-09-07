## Verdict

exploitable

## Source

`r.URL.Query().Get("file")` (line 12) — untrusted user input from HTTP query parameter

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
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Make the base directory absolute
	absBase, err := filepath.Abs(docsRoot)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Join and clean the path
	path := filepath.Join(absBase, name)
	cleanPath := filepath.Clean(path)

	// Verify the resolved path is contained within the base directory
	if cleanPath != absBase && !strings.HasPrefix(cleanPath, absBase+string(filepath.Separator)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Use only the validated path for the file operation
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}
```

## Explanation

The original code joins the untrusted `name` parameter directly with the base directory using `filepath.Join`, but performs no validation that the resulting path stays within `docsRoot`. While `filepath.Join` and `filepath.Clean` normalize path syntax (resolving `.` and `..` sequences), they do not enforce directory boundaries. An attacker can supply inputs like `../../etc/passwd` to escape the intended directory and read arbitrary files.

The fix implements the core CWE-22 remediation: (1) reject absolute paths and inputs starting with `..` before joining, (2) make the base directory absolute with `filepath.Abs` to enable reliable comparison, (3) clean the joined path, and (4) verify containment by checking that the canonical path equals the base or starts with the base followed by the path separator. Only the validated path variable is passed to `os.ReadFile`, breaking taint after the allowlist validation succeeds. Invalid traversal attempts now return HTTP 403 Forbidden instead of granting access.

## Behaviour changes

- Added validation branch that rejects absolute paths and paths starting with `..`, returning HTTP 403 Forbidden
- Added error handling for `filepath.Abs` call on the base directory; errors return HTTP 500 Internal Server Error
- Added path containment verification that rejects resolved paths escaping the base directory, returning HTTP 403 Forbidden
- Changed from using the result of `filepath.Join(docsRoot, name)` directly to using the validated and canonicalized absolute path; the sink contract (reading file contents via `os.ReadFile`) remains intact but now receives a verified path

