## Verdict

CONFIRMED: Path traversal via sibling directory prefix bypass.

## Source

Line 20: `requestedFile := r.URL.Query().Get("file")` - untrusted user input from HTTP query parameter

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
	if !(full == uploadsDir || strings.HasPrefix(full, uploadsDir+string(filepath.Separator))) {
		http.Error(w, "invalid file path", http.StatusForbidden)
		return
	}

	http.ServeFile(w, r, full)
}
```

## Explanation

The original containment check on line 31 used `strings.HasPrefix(full, uploadsDir)` to verify that the canonicalized path stays within the allowed directory. This is vulnerable to sibling directory prefix bypass: a path like `/srv/app/uploads-backup/file.txt` would pass the check because it has the string prefix `/srv/app/uploads`, even though it exists in a sibling directory outside the intended access scope.

The fix replaces this with `full == uploadsDir || strings.HasPrefix(full, uploadsDir+string(filepath.Separator))`, which adds path-component-aware boundary checking using the filesystem separator. This ensures:

1. The path equals the base directory exactly, OR
2. The path starts with the base directory followed by a separator (`/`), which prevents sibling directories from matching

This follows the Go-specific guidance: "the separator is what stops a sibling directory matching" and implements the safe pattern of checking `full == base || strings.HasPrefix(full, base+string(filepath.Separator))`.

The fix correctly preserves all aspects of the original function:
- `filepath.Join` and `filepath.Clean` continue to normalize path syntax
- The check still rejects `..` sequences and other traversal attempts
- Only the canonicalized path `full` is passed to the sink (`http.ServeFile`)
- Error handling remains unchanged

## Behaviour changes

**Before fix**: Request with `?file=../uploads-backup/snapshot.tar.gz` would bypass the containment check and serve files from the sibling backup directory.

**After fix**: The same request is correctly rejected with HTTP 403 Forbidden, as the sibling directory path fails the boundary check due to the missing separator component.
