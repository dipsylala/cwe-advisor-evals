## Verdict

Exploitable

## Source

User-controlled input from `r.URL.Query().Get("file")` on line 20 flows to the path-traversal sink at line 37 (`http.ServeFile`). The vulnerability exists in the containment check on line 31, which uses a string prefix match without a path separator, allowing access to sibling directories.

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
	// Use path separator to prevent sibling directory access:
	// HasPrefix alone would allow "/srv/app/uploads-backup" when base is "/srv/app/uploads"
	if !(full == uploadsDir || strings.HasPrefix(full, uploadsDir+string(filepath.Separator))) {
		http.Error(w, "invalid file path", http.StatusForbidden)
		return
	}

	http.ServeFile(w, r, full)
}
```

## Explanation

The original code used `strings.HasPrefix(full, uploadsDir)` to verify the canonicalized path stayed within the uploads directory. This check is insufficient: a path like `/srv/app/uploads-backup/file.txt` passes the prefix test because it starts with the string `/srv/app/uploads`, even though it is outside the intended directory. The fix adds the path separator to the containment check: `full == uploadsDir || strings.HasPrefix(full, uploadsDir+string(filepath.Separator))`. This ensures the path either equals the base directory exactly or is a true child of it by requiring the directory separator after the base path. With this change, `/srv/app/uploads-backup/file.txt` correctly fails the check, while legitimate files like `/srv/app/uploads/file.txt` and `/srv/app/uploads/subdir/file.txt` still pass.

## Behaviour changes

None. The fix preserves the sink contract: `http.ServeFile` still receives an absolute, canonicalized path that has been validated to exist within the base directory. The function's return value and error handling remain unchanged. The only behavioural difference is that requests attempting sibling-directory traversal (e.g., `?file=../uploads-backup/secrets.txt`) are now correctly rejected with HTTP 403 Forbidden, where they would previously have been served in the vulnerable version.
