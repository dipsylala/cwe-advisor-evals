## Verdict

True positive. The code is vulnerable to path traversal via the `file` query parameter.

## Source

Line 12 reads untrusted input: `name := r.URL.Query().Get("file")`

Line 18 joins this with a base directory: `path := filepath.Join(docsRoot, name)`

An attacker can provide input like `../../etc/passwd` to escape the base directory and read arbitrary files.

## Fix

Validate that the resolved path remains within the intended directory by computing the relative path and checking it does not escape:

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

	path := filepath.Join(docsRoot, name)
	
	// Verify the resolved path is within docsRoot
	rel, err := filepath.Rel(docsRoot, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		http.Error(w, "invalid file path", http.StatusForbidden)
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

After joining the user input with the base directory, use `filepath.Rel()` to compute the relative path back to the base directory. If the relative path starts with `..`, it indicates the resolved path escapes the intended directory, and the request is rejected with a 403 Forbidden status. This prevents path traversal attacks while still allowing legitimate relative paths within the docs directory.

