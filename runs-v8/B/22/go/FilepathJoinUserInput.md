## Verdict

Exploitable

## Source

Line 12: `name := r.URL.Query().Get("file")` - untrusted user input from HTTP query parameter

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

	// Reject absolute paths and traversal attempts
	if filepath.IsAbs(name) || strings.HasPrefix(name, "..") {
		http.Error(w, "invalid file parameter", http.StatusBadRequest)
		return
	}

	// Construct, clean, and canonicalize the path
	absBase, err := filepath.Abs(docsRoot)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	path := filepath.Clean(filepath.Join(absBase, name))

	// Verify containment within the base directory
	if path != absBase && !strings.HasPrefix(path, absBase+string(filepath.Separator)) {
		http.Error(w, "forbidden", http.StatusForbidden)
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

The vulnerability occurs because `filepath.Join` and `filepath.Clean` normalize path syntax (resolving `.` and `..` sequences) but do not verify that the resulting path remains within the intended base directory. An attacker passing traversal sequences like `../../etc/passwd` escapes `docsRoot` entirely.

The fix implements three layers of defence per the CWE-22 Go guidance:

1. **Early rejection** of absolute paths and paths starting with `..` eliminates obvious traversal attempts
2. **Absolute canonicalization** converts the base directory to an absolute path and joins it before cleaning, ensuring consistent comparison
3. **Containment verification** confirms the final path is either the base itself or is strictly inside it by checking for the separator, which prevents sibling directories matching a string prefix

The validation occurs before `os.ReadFile` receives the path, breaking taint at the validation point. The containment check uses the pattern `path != absBase && !strings.HasPrefix(path, absBase+string(filepath.Separator))`, which correctly handles both the base directory itself and paths inside it while rejecting any escape attempt.

## Behaviour changes

- Added `strings` import to support prefix checking
- Added three validation blocks before `os.ReadFile`: absolute path rejection, base directory absolutization with error handling, and containment verification returning HTTP 403 Forbidden on failure
- `os.ReadFile` still receives the same arguments and produces the same return values; error handling is identical

These changes preserve the sink contract: `os.ReadFile` still returns `([]byte, error)`, still writes HTTP 200 with the file data on success, and still returns HTTP 404 on read errors. The new error responses (400 for invalid input, 500 for base resolution failure, 403 for containment violation) correctly signal attack attempts without leaking path information.
