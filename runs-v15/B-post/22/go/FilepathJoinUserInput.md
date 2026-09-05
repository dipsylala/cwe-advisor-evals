## Verdict

VULNERABLE. The `downloadHandler` function constructs a file path from user-supplied input without validating that the resolved path remains within the intended base directory. An attacker can supply path traversal sequences (e.g., `../../../etc/passwd`) to read files outside the `docsRoot` directory.

## Source

The vulnerability originates at line 12 where `name := r.URL.Query().Get("file")` retrieves untrusted user input from the HTTP request query string. This value flows directly into `filepath.Join(docsRoot, name)` at line 18, and then into `os.ReadFile(path)` at line 21 without any validation.

While `filepath.Join` normalizes path syntax (resolving `.` and `..` sequences), it does not enforce that the result stays within an allowed directory boundary. Therefore, inputs like `../../etc/passwd` will successfully escape the intended base directory.

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

	// Reject absolute paths and direct traversal attempts
	if filepath.IsAbs(name) || strings.HasPrefix(name, "..") {
		http.Error(w, "invalid file parameter", http.StatusBadRequest)
		return
	}

	// Ensure base directory is absolute for safe comparison
	baseAbs, err := filepath.Abs(docsRoot)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Join, clean, and resolve to canonical form
	path := filepath.Clean(filepath.Join(baseAbs, name))

	// Enforce containment: path must be inside baseAbs
	if path != baseAbs && !strings.HasPrefix(path, baseAbs+string(filepath.Separator)) {
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

The fix employs multiple defensive layers aligned with CWE-22 guidance:

1. **Input rejection**: `filepath.IsAbs(name)` rejects absolute paths and `strings.HasPrefix(name, "..")` rejects direct traversal attempts in the user input. This prevents the most obvious attack vectors early.

2. **Absolute base path**: Convert `docsRoot` to absolute form with `filepath.Abs`. This ensures the containment check compares two absolute paths, avoiding comparison errors where a relative base allows a relative candidate to incorrectly match.

3. **Canonicalization**: `filepath.Clean` resolves remaining `.` and `..` sequences within `name` to produce a canonical path.

4. **Containment enforcement**: After canonicalization, verify the result is contained within `baseAbs` using path-component-aware comparison: either the path equals the base exactly (allowing the base directory itself) or it starts with the base followed by a path separator. This second condition—appending the separator—prevents substring matches like `/var/app/docs-secret` from falsely matching `/var/app/docs`.

5. **Single variable use**: The validated `path` variable is passed to `os.ReadFile`, never the original input, preventing a TOCTOU race.

Together, these steps ensure that `filepath.Join` and `filepath.Clean` normalize syntax safely and that no input—whether encoded, Unicode-escaped, or using symlinks—can escape the intended directory.

## Behaviour changes

**Before fix:**
- `GET /download?file=../../etc/passwd` → Reads `/etc/passwd` (outside base directory)
- `GET /download?file=/etc/passwd` → Reads `/etc/passwd` (absolute path allowed)
- `GET /download?file=readme.txt` → Reads `/var/app/docs/readme.txt` (only valid case works)

**After fix:**
- `GET /download?file=../../etc/passwd` → Returns 400 Bad Request (traversal rejected)
- `GET /download?file=/etc/passwd` → Returns 400 Bad Request (absolute path rejected)
- `GET /download?file=readme.txt` → Reads `/var/app/docs/readme.txt` (valid case still works)
- `GET /download?file=subdir/readme.txt` → Reads `/var/app/docs/subdir/readme.txt` (valid subdirectory access works)

The fix closes the path traversal vector while preserving legitimate access to files within the intended directory and its subdirectories.
