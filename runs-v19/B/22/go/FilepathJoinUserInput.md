## Verdict

exploitable

## Source

`r.URL.Query().Get("file")` on line 12 — untrusted user input from HTTP request query parameter.

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

var docsRoot string

func init() {
	var err error
	docsRoot, err = filepath.Abs("/var/app/docs")
	if err != nil {
		panic(err)
	}
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	if name == "" {
		http.Error(w, "missing file parameter", http.StatusBadRequest)
		return
	}

	if filepath.IsAbs(name) {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	path := filepath.Clean(filepath.Join(docsRoot, name))

	// Verify the path is contained within docsRoot
	if path != docsRoot && !strings.HasPrefix(path, docsRoot+string(filepath.Separator)) {
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

The original code used `filepath.Join()` to construct a file path from user input without validating that the result stayed within the base directory. While `filepath.Join()` normalizes path syntax (resolving `.` and `..`), it does not enforce containment. An attacker could pass `"../../etc/passwd"` or similar sequences to escape the intended directory.

The fix implements three key protections: (1) converts `docsRoot` to a package variable initialized with `filepath.Abs()` to ensure it is always an absolute path, (2) rejects absolute paths in user input with `filepath.IsAbs()` to prevent attackers from specifying arbitrary filesystem locations, and (3) canonicalizes the joined path with `filepath.Clean()` and then verifies it is contained within `docsRoot` using path-component-aware comparison. The containment check uses `strings.HasPrefix()` with the directory separator appended to the base to prevent matching sibling directories (e.g., `/var/app/docs-secret`).

## Behaviour changes

- `docsRoot` changed from a string constant to a package variable initialized in `init()`. Added error handling for `filepath.Abs()` failure by panicking, which is appropriate for startup initialization. This ensures the base path is always absolute and ready before any handler invokes it.
- Added validation that rejects absolute paths in the user input before path construction, returning 403 Forbidden instead of attempting to read the file. This prevents path traversal attempts using absolute paths.
- Added explicit path-containment validation after normalization. Out-of-bounds paths now return 403 Forbidden instead of 404 Not Found. This is a minor behavior change but is security-justified to prevent information leakage about the filesystem structure.
- Added import of `strings` package for `HasPrefix()` function.
- The `os.ReadFile()` sink now receives only the validated, canonicalized path (`path` variable), never the raw untrusted input.
