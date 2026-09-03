## Verdict
The code contains a path traversal vulnerability. User-supplied input (`name` parameter) is joined with a base directory but never validated to ensure it stays within that directory. An attacker can use path traversal sequences like `../` to access files outside the intended directory.

## Source
Line 18-21: The `name` parameter from the HTTP query string is directly joined with `docsRoot` to construct a file path, then immediately passed to `os.ReadFile()` without validation that the resolved path remains within the base directory.

```
path := filepath.Join(docsRoot, name)
data, err := os.ReadFile(path)
```

An attacker requesting `?file=../../../etc/passwd` would cause `filepath.Join()` to construct `/var/app/docs/../../../etc/passwd`, which the OS resolves to `/etc/passwd`, allowing arbitrary file access.

## Fix
After joining the paths, clean the result and verify it stays within the base directory. Use `filepath.Rel()` to compute the relative path from the base directory; if it starts with `..`, reject it:

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
	cleanPath := filepath.Clean(path)

	// Verify the path stays within the base directory
	rel, err := filepath.Rel(docsRoot, cleanPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

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
The fix adds a path validation check before reading the file. 

1. `filepath.Clean()` normalizes the path by resolving `.` and `..` sequences.
2. `filepath.Rel()` computes the relative path from `docsRoot` to the cleaned path. If the file is within the base directory, the result is a relative path without `..`. If the file is outside (path traversal), the relative path starts with `..`.
3. The check rejects any path that either fails `filepath.Rel()` or has a relative path starting with `..`, preventing directory escape.

This ensures that only files within `/var/app/docs` and its subdirectories can be accessed, regardless of the user input.
