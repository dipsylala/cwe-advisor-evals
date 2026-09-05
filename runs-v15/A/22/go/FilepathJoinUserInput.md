## Verdict

Path traversal vulnerability confirmed. The `name` parameter from the query string is joined directly with the base directory without validation, allowing an attacker to escape the intended directory using `../` sequences.

## Source

The vulnerability is in the `downloadHandler` function at line 18:

```go
path := filepath.Join(docsRoot, name)
```

User-supplied `name` comes from the HTTP query string without validation. An attacker can request `?file=../../../../etc/passwd` to read arbitrary files outside `docsRoot`.

## Fix

Add validation to ensure the resolved path stays within the intended directory:

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

	// Clean the input path to normalize it
	cleanName := filepath.Clean(name)
	
	// Reject any path that attempts to escape the base directory
	if strings.HasPrefix(cleanName, "..") || strings.Contains(cleanName, string(filepath.Separator)+".."+string(filepath.Separator)) {
		http.Error(w, "invalid file parameter", http.StatusBadRequest)
		return
	}

	path := filepath.Join(docsRoot, cleanName)
	
	// Verify the final resolved path is within docsRoot
	absPath, err := filepath.Abs(path)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	
	absRoot, err := filepath.Abs(docsRoot)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	
	// Ensure the path is within the root (with proper directory separator handling)
	if !strings.HasPrefix(absPath, absRoot+string(filepath.Separator)) && absPath != absRoot {
		http.Error(w, "invalid file parameter", http.StatusBadRequest)
		return
	}

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

The fix uses a defense-in-depth approach:

1. **Input normalization**: `filepath.Clean()` normalizes the path, converting sequences like `..` into their canonical form.

2. **Explicit rejection of traversal patterns**: Check if the cleaned path starts with `..` or contains `/../`, which are the attack patterns for directory traversal.

3. **Absolute path verification**: Convert both the constructed path and the base directory to absolute paths, eliminating ambiguity from symlinks or relative path components.

4. **Boundary validation**: Verify the final absolute path is within the base directory by checking that it starts with `absRoot + filepath.Separator`. This is the definitive check that prevents escape.

The validation rejects requests like `?file=../../../../etc/passwd` before they reach `os.ReadFile()`, ensuring only files within `/var/app/docs` can be accessed.
