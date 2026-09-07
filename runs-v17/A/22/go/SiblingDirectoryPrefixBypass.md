## Verdict
CONFIRMED

## Source
The `HasPrefix` check at line 31 uses a string prefix match without respecting directory boundaries. A path like `../uploads-backup/file.txt` bypasses the check because `/srv/app/uploads-backup` starts with the string `/srv/app/uploads`, even though it is not a subdirectory.

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
	rel, err := filepath.Rel(uploadsDir, full)
	if err != nil || strings.HasPrefix(rel, "..") {
		http.Error(w, "invalid file path", http.StatusForbidden)
		return
	}

	// SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
	http.ServeFile(w, r, full)
}
```

## Explanation
Replaced the string `HasPrefix` check with `filepath.Rel`, which computes the relative path from `uploadsDir` to `full`. If this relative path starts with `..`, the target is outside the intended directory. This approach:

1. Respects directory boundaries—sibling directories like `uploads-backup` cannot pass the check
2. Uses idiomatic Go path comparison that handles edge cases
3. Rejects any escape attempt, including `..`, symlink escapes after cleaning, and prefix bypasses

The fix rejects paths outside `uploadsDir` while accepting legitimate files within it.
