## Verdict

Exploitable. User-supplied input from the HTTP query parameter flows to `filepath.Join` without validation, allowing path traversal. While `filepath.Join` normalizes syntax, it does not enforce directory boundary constraints, permitting escape via sequences like `../../etc/passwd`.

## Source

HTTP query parameter `file` (line 12):
```go
name := r.URL.Query().Get("file")
```

## Fix

**Vulnerable code:**
```go
path := filepath.Join(docsRoot, name)

// SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
data, err := os.ReadFile(path)
```

**Fixed code:**
```go
// Reject absolute paths and traversal attempts
if filepath.IsAbs(name) || strings.Contains(name, "..") {
	http.Error(w, "invalid file parameter", http.StatusBadRequest)
	return
}

path := filepath.Join(docsRoot, name)

// Canonicalize and verify containment within docsRoot
absPath, err := filepath.Abs(path)
if err != nil {
	http.Error(w, "internal error", http.StatusInternalServerError)
	return
}

absRoot, err := filepath.Abs(docsRoot)
if err != nil {
	http.Error(w, "internal error", http.StatusInternalServerError)
	return
}

// Verify the resolved path is within the base directory
if absPath != absRoot && !strings.HasPrefix(absPath, absRoot+string(filepath.Separator)) {
	http.Error(w, "access denied", http.StatusForbidden)
	return
}

data, err := os.ReadFile(absPath)
```

**Required import addition:**
```go
import (
	"net/http"
	"os"
	"path/filepath"
	"strings"  // ADD THIS
)
```

## Explanation

The fix applies three-layer path validation per CWE-22/go guidance. First, it rejects absolute paths (`filepath.IsAbs`) and traversal sequences (`strings.Contains(name, "..")`) before any path construction, blocking attacks at the input layer. Second, it canonicalizes both the candidate path and the base directory with `filepath.Abs`, converting them to absolute form to enable reliable comparison. Third, it verifies containment: the resolved path must either equal the base directory exactly or start with the base path plus a separator. The separator check prevents a sibling directory like `/var/app/docs-secret` from matching a prefix of `/var/app/docs`. The fix uses only the canonicalized `absPath` for the actual `os.ReadFile` call, never re-deriving the path from the original untrusted input.

## Behaviour changes

- Added validation rejecting absolute paths and `..` sequences, returning HTTP 400. Requests with these patterns now fail closed instead of attempting the access.
- Added `filepath.Abs` calls on both paths, which may fail on filesystem access issues (returns HTTP 500). Original code had no such error handling for path canonicalization, but paths are already system-controlled, so this surfaces only exceptional failures.
- Added containment check with HTTP 403 rejection, returning access-denied instead of not-found when the resolved path falls outside `docsRoot`. This trades information visibility (the file may or may not exist, attacker no longer learns which) for security (prevents any information leakage from files outside the intended directory).
- File operation now reads from `absPath` (canonicalized) instead of `path` (derived from untrusted input). This ensures the sink operates on the validated canonical form, not a re-derived path.
