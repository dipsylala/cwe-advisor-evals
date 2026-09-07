## Verdict
CONFIRMED

## Source
User-supplied filename from `r.URL.Query().Get("file")` (line 12) flows to `filepath.Join()` (line 18) and then to `os.ReadFile()` (line 21) without validation that the resolved path remains within the restricted directory.

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

	path := filepath.Join(docsRoot, name)

	// Ensure the requested path is still within the docs root
	rel, err := filepath.Rel(docsRoot, path)
	if err != nil || strings.HasPrefix(rel, "..") {
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
After joining the user-supplied filename with the root directory, the fix computes the relative path from `docsRoot` to the final resolved path using `filepath.Rel()`. If the relative path starts with `..` or if `filepath.Rel()` returns an error (indicating the paths are on different volumes or incompatible), the request is rejected with a 404. This prevents directory traversal attacks: an attacker attempting `../../../etc/passwd` will have its relative path start with `..` and be blocked, while legitimate requests for files within the docs directory will pass the check.
