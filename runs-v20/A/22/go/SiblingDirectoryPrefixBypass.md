## Verdict

Confirmed. The containment check at line 31 is a raw string-prefix comparison, which does not verify that the cleaned path is actually inside `uploadsDir` — it only verifies that the path's textual representation starts with the same characters.

## Source

`requestedFile := r.URL.Query().Get("file")` in `DownloadHandler` (line 20) — an HTTP query parameter, fully attacker-controlled.

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

	// Containment check: confirm the cleaned path is uploadsDir itself or
	// lives inside it. filepath.Rel reports how full relates to uploadsDir;
	// a result of ".." or one starting with "../" means full escaped the
	// directory (including into a sibling such as uploads-backup that
	// merely shares uploadsDir's string prefix).
	rel, err := filepath.Rel(uploadsDir, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		http.Error(w, "invalid file path", http.StatusForbidden)
		return
	}

	http.ServeFile(w, r, full)
}
```

## Explanation

`strings.HasPrefix(full, uploadsDir)` treats `uploadsDir` as a plain character sequence, not a directory boundary. Because `"/srv/app/uploads-backup/..."` also begins with the characters `"/srv/app/uploads"`, a request such as `?file=../uploads-backup/secret.txt` cleans to `/srv/app/uploads-backup/secret.txt`, which passes the prefix check even though it is a completely different, sibling directory outside the intended tree — exactly the backup directory the comment says must never be reachable. `filepath.Join` and `filepath.Clean` do not stop this: they only normalize `.` and `..` segments, they don't enforce that the result stays under a given root.

The fix replaces the prefix comparison with `filepath.Rel(uploadsDir, full)`. `Rel` computes the relative path needed to get from `uploadsDir` to `full`; if `full` is outside `uploadsDir`, the result either is `".."` or begins with `"../"` (using the OS-specific separator). Checking for that condition — along with the error `Rel` returns when the two paths can't be related at all (e.g. different volume on Windows) — correctly rejects any candidate that isn't `uploadsDir` itself or a genuine descendant of it, while still allowing legitimate nested filenames. This closes the sibling-directory bypass without changing behavior for any valid upload path.
