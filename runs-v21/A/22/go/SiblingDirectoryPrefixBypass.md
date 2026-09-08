## Verdict
CONFIRMED - Path traversal via string prefix bypass. The containment check using `strings.HasPrefix(full, uploadsDir)` fails to distinguish between the intended directory `/srv/app/uploads` and a sibling directory like `/srv/app/uploads-backup`, allowing access to files outside the intended scope.

## Source
The vulnerability originates from the `requestedFile` query parameter at line 20, which flows through `filepath.Join()` and `filepath.Clean()` at lines 26-27, then to the faulty containment check at line 31.

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
	// uploadsDir before serving it back to the client. Require an exact
	// match or a path that starts with uploadsDir/ (with separator) to
	// prevent sibling directory traversal such as /srv/app/uploads-backup.
	if full != uploadsDir && !strings.HasPrefix(full, uploadsDir+string(filepath.Separator)) {
		http.Error(w, "invalid file path", http.StatusForbidden)
		return
	}

	// SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
	http.ServeFile(w, r, full)
}
```

## Explanation
The original check `strings.HasPrefix(full, uploadsDir)` matches string prefixes without verifying actual directory containment. This allows an attacker to access sibling directories whose names happen to begin with the uploads directory's name - for example, `/srv/app/uploads-backup` begins with the string `/srv/app/uploads` and passes the check despite being a sibling, not a child.

The fix ensures true containment by verifying that either:
1. The path is exactly `uploadsDir` itself, OR
2. The path starts with `uploadsDir` followed by the path separator character

This forces a proper directory boundary check that rejects requests trying to escape to adjacent directories while permitting legitimate access to files within the uploads tree.
