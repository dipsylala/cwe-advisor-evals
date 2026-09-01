## Verdict
Confirmed. User input `name` from the URL query parameter flows unsanitized through `filepath.Join()` to `os.ReadFile()`, allowing path traversal attacks to read files outside the intended `docsRoot` directory.

## Source
Line 12: User-supplied filename from URL query parameter.
Line 18: `filepath.Join()` does not prevent path traversal sequences like `../../`.
Line 21: `os.ReadFile()` reads the traversed path without validation.

An attacker can request `?file=../../etc/passwd` to read arbitrary files on the system.

## Fix
After joining the path, normalize it and verify it remains within the intended directory by checking the relative path for upward traversal:

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

	// Join user input with the safe base directory
	path := filepath.Join(docsRoot, name)
	
	// Clean the path to normalize it
	path = filepath.Clean(path)
	
	// Verify the path is within docsRoot by checking the relative path
	rel, err := filepath.Rel(docsRoot, path)
	if err != nil || strings.HasPrefix(rel, "..") {
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
The fix validates the resolved path by computing its relative path from `docsRoot`. If the relative path starts with `..`, it indicates an upward traversal attempt and is rejected with HTTP 403 Forbidden.

`filepath.Clean()` normalizes the path (removes redundant separators and `.` components) before validation, ensuring that techniques like `docs/./../../etc/passwd` are caught.

`filepath.Rel()` determines how the cleaned path relates to the root; if the result begins with `..`, the path escapes the safe directory and is rejected before any file operation occurs.

This approach prevents both direct traversal sequences (`../`) and obfuscated variants while remaining portable across Windows and Unix-like systems.
