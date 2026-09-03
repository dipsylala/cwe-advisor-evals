## Verdict

Exploitable path traversal vulnerability. The application constructs file paths by joining user-supplied query parameter `file` directly with the base directory using `filepath.Join`. Because `filepath.Join` only normalizes path syntax without enforcing directory containment, attackers can use traversal sequences like `../` to read arbitrary files outside `/var/app/docs`.

## Source

Line 12: `name := r.URL.Query().Get("file")` - attacker-controlled query parameter.

## Fix

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

	// Reject absolute paths and obvious traversal attempts
	if filepath.IsAbs(name) || strings.Contains(name, "..") {
		http.Error(w, "invalid file path", http.StatusBadRequest)
		return
	}

	// Resolve base to absolute path
	base, err := filepath.Abs(docsRoot)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Join, clean, and verify containment
	full := filepath.Join(base, name)
	full = filepath.Clean(full)

	// Enforce that the resolved path is contained within docsRoot
	if full != base && !strings.HasPrefix(full, base+string(filepath.Separator)) {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	// Use only the validated path for file access
	data, err := os.ReadFile(full)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}
```

## Explanation

The fix introduces three layers of containment:

1. **Reject obvious traversal:** Early check rejects absolute paths (`filepath.IsAbs`) and paths containing `..`, filtering the most direct attack vectors before path construction.

2. **Canonicalize and verify containment:** After joining the user input with the base directory, `filepath.Clean` resolves any remaining `.` or `..` sequences. The result is then checked against the base directory using `strings.HasPrefix(full, base+separator)`. The separator check prevents sibling-directory matching (e.g., `/app/docs-backup` passing a check for `/app/docs` without it).

3. **Break taint:** The validation result (`full`) is assigned to a separate variable and used for the subsequent `os.ReadFile` call, ensuring the file operation uses only the validated path, never the original untrusted input.

Together, these enforce that any file accessed stays within the intended directory, closing the path traversal vulnerability while preserving normal file-serving functionality.

## Behaviour changes

- Requests with absolute paths or `..` sequences now return HTTP 400 (Bad Request) instead of potentially serving files outside the intended directory.
- Requests attempting to escape the base directory return HTTP 403 (Forbidden) instead of potentially succeeding.
- All file access now uses the canonicalized, validated path.
- No change to successful requests within the intended directory.
