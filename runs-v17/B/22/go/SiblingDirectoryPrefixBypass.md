## Verdict

**CONFIRMED: CWE-22 Path Traversal** - The containment check uses a string prefix that does not account for path separators, allowing attackers to access sibling directories with names that share the base directory's prefix.

## Source

**File:** `uploads_download.go`
**Line:** 31 (containment check); vulnerability is exploitable at line 37 (sink)

**Data Flow:**
1. Attacker-supplied filename enters via `r.URL.Query().Get("file")` (line 20)
2. Joined with uploadsDir via `filepath.Join()` (line 26)
3. Normalized via `filepath.Clean()` (line 27)
4. Checked for containment at line 31 using `strings.HasPrefix(full, uploadsDir)`
5. Path is served via `http.ServeFile(w, r, full)` (line 37)

**Exploitable Path:**
- Input: `file=../../../../srv/app/uploads-backup/secret`
- After filepath.Join: `/srv/app/uploads/../../../../srv/app/uploads-backup/secret`
- After filepath.Clean: `/srv/app/uploads-backup/secret`
- Containment check: `strings.HasPrefix("/srv/app/uploads-backup/secret", "/srv/app/uploads")` returns `true` (because "uploads-backup" contains "uploads" as a string prefix, not a path component)
- Result: Attacker gains access to `/srv/app/uploads-backup/secret` instead of being confined to `/srv/app/uploads`

## Fix

### File: uploads_download.go

```go
// Package uploads implements the HTTP handler that serves files previously
// stored by users under the shared uploads directory.
package uploads

import (
	"net/http"
	"path/filepath"
	"strings"
)

// uploadsDir is the directory tree that user uploads are confined to. A
// sibling directory, uploads-backup, holds periodic snapshots taken by an
// unrelated backup job and must never be reachable from this handler.
const uploadsDir = "/srv/app/uploads"

// DownloadHandler serves a single previously uploaded file back to the
// owning user. The file name is supplied as a query parameter and is
// expected to resolve to something inside uploadsDir.
func DownloadHandler(w http.ResponseWriter, r *http.Request) {
	requestedFile := r.URL.Query().Get("file")
	if requestedFile == "" {
		http.Error(w, "file parameter is required", http.StatusBadRequest)
		return
	}

	candidate := filepath.Join(uploadsDir, requestedFile)
	full := filepath.Clean(candidate)

	// Containment check: confirm the cleaned path still lives under
	// uploadsDir before serving it back to the client.
	if full != uploadsDir && !strings.HasPrefix(full, uploadsDir+string(filepath.Separator)) {
		http.Error(w, "invalid file path", http.StatusForbidden)
		return
	}

	http.ServeFile(w, r, full)
}
```

## Explanation

The vulnerability exists because the original containment check at line 31 uses `strings.HasPrefix(full, uploadsDir)` without accounting for path component boundaries. This allows any path beginning with the string "/srv/app/uploads" to pass, including sibling directories like "/srv/app/uploads-backup".

The fix enforces proper path-component-aware containment by checking that the resolved path either:
1. Equals the base directory exactly (`full != uploadsDir`), or
2. Starts with the base directory followed by a path separator (`strings.HasPrefix(full, uploadsDir+string(filepath.Separator))`)

This pattern is the Go-specific safe validation recommended in CWE-22's remediation guidance: "After joining and cleaning, verify the resulting absolute path is contained within the base directory using `full == base || strings.HasPrefix(full, base+string(filepath.Separator))`".

The fix changes only the containment check logic and preserves all other behavior: the path is still cleaned before validation, and the same `http.ServeFile` sink is used with the validated path. No changes to imports, error handling, or return values.

## Behaviour changes

**Before:** Paths like `/srv/app/uploads-backup/secret` incorrectly pass the containment check and are served.

**After:** Only paths that are either the uploads directory itself or files/subdirectories within `/srv/app/uploads/` are served; any attempt to access `/srv/app/uploads-backup/` or other sibling directories is rejected with HTTP 403 Forbidden.

**Test cases that now correctly fail (before they incorrectly passed):**
- `file=../../../../srv/app/uploads-backup/secret` → HTTP 403 (previously would serve from uploads-backup)
- Any path with prefix `/srv/app/uploads` but without a separator after it (e.g., any access to the sibling `/srv/app/uploads-*` directories) → HTTP 403
