## Verdict

Exploitable

## Source

HTTP request query parameter `file` (line 12)

## Fix

**Vulnerable code:**
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
	// ...
}
```

**Fixed code:**
```go
import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	if name == "" {
		http.Error(w, "missing file parameter", http.StatusBadRequest)
		return
	}

	// Reject absolute paths and traversal attempts
	if filepath.IsAbs(name) || strings.HasPrefix(name, "..") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Resolve base to absolute path for containment check
	baseAbs, err := filepath.Abs(docsRoot)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Join and canonicalize
	path := filepath.Join(baseAbs, name)
	path = filepath.Clean(path)

	// Verify containment within base directory
	if path != baseAbs && !strings.HasPrefix(path, baseAbs+string(filepath.Separator)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Use canonical path for file operation
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

The original code joins user-supplied input directly to the base directory without validating that the result stays within bounds. `filepath.Join` and `filepath.Clean` normalize path syntax (resolving `.` and `..` sequences) but do not enforce containment, so an attacker can use `../` sequences to traverse outside the intended directory. The fix adds three layers: (1) reject traversal patterns upfront (absolute paths and leading `..`), (2) resolve the base to an absolute path to ensure containment comparison is consistent, and (3) verify the canonicalized result is either the base itself or contained within it using path-component-aware comparison (`HasPrefix` with the separator appended). The canonical path from `filepath.Clean` is then used for `os.ReadFile`, ensuring the sink receives only validated input.

## Behaviour changes

- **Added filepath.Abs() call on base directory**: Resolves `docsRoot` to an absolute path once at the start of the security check. This is necessary because boundary checks comparing a relative base against an absolute candidate will always fail. Reason: Go's path comparison cannot be done safely without both paths in the same form.
- **Added validation checks (IsAbs, HasPrefix "..") before filepath.Join**: Rejects inputs that are absolute paths or start with traversal sequences. Reason: Early rejection prevents dangerous paths from ever reaching the filesystem operation and surfaces the attempt in behavior (forbidden error) rather than silently dropping characters.
- **Added containment verification after filepath.Clean**: Compares the resolved path against the base using `== base || HasPrefix(full, base+separator)`. Reason: This is the primary boundary enforcement per CWE-22 guidance—string-only comparison without the separator is bypassable by sibling directories.
- **Used canonical path variable for os.ReadFile**: The `path` variable from `filepath.Clean` is passed to `os.ReadFile`, never the original `name` input. Reason: Ensures the sink operates only on the validated, canonical value.
- **Imported "strings" package**: Added to support the validation and containment checks. Reason: Required for HasPrefix and traversal pattern validation.
