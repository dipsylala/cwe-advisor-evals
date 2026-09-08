## Verdict

exploitable

## Source

User-supplied `file` query parameter from `r.URL.Query().Get("file")` on line 20.

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

	// SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
	http.ServeFile(w, r, full)
}
```

## Explanation

The original containment check used `strings.HasPrefix(full, uploadsDir)` without including the path separator, allowing sibling directory traversal. When `uploadsDir = "/srv/app/uploads"` and the user requests `../uploads-backup/secret.txt`, the canonicalized path becomes `/srv/app/uploads-backup/secret.txt`, which passes the flawed string prefix check because it begins with `/srv/app/uploads`. The fixed check appends `filepath.Separator` to the base directory and also permits the base directory itself with an equality check: `full != uploadsDir && !strings.HasPrefix(full, uploadsDir+string(filepath.Separator))`. This path-component-aware comparison prevents sibling directories from matching while still allowing any file or subdirectory legitimately beneath the allowed root.

## Behaviour changes

None. The fix preserves the sink contract: `http.ServeFile` receives the same canonicalized `full` variable that passed a corrected containment check. No changes to error handling, return values, or implicit arguments.

