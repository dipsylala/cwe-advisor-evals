## Verdict

Confirmed exploitable. CWE-22, Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal').

## Source

`r.URL.Query().Get("file")` in `DownloadHandler` (`uploads_download.go:20`) - the `file` query parameter, fully attacker-controlled.

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

	// Containment check: confirm the cleaned path is uploadsDir itself or a
	// descendant of it. Comparing against uploadsDir plus a trailing
	// separator (rather than a bare string prefix) stops a sibling
	// directory whose name happens to start with the same characters, such
	// as uploads-backup, from matching.
	if full != uploadsDir && !strings.HasPrefix(full, uploadsDir+string(filepath.Separator)) {
		http.Error(w, "invalid file path", http.StatusForbidden)
		return
	}

	http.ServeFile(w, r, full)
}
```

## Explanation

`filepath.Join`/`filepath.Clean` only normalize `.`/`..` syntax; they do not enforce a security boundary. The existing check, `strings.HasPrefix(full, uploadsDir)`, is a raw string-prefix test with no separator between the base and the rest of the path, so any sibling directory whose name extends the base string - here `/srv/app/uploads-backup` - passes the same test as a real descendant of `/srv/app/uploads`. A request for `file=../uploads-backup/<name>` cleans to `/srv/app/uploads-backup/<name>`, which starts with the literal characters `/srv/app/uploads` and slips through, reaching the backup snapshot tree the comment says must stay unreachable. The fix keeps every existing step - join, clean, containment check, then `http.ServeFile` on the checked variable - and only tightens the containment test to `full == uploadsDir || strings.HasPrefix(full, uploadsDir+string(filepath.Separator))`: the separator after the base means only `uploadsDir` itself or a true path-component descendant of it can match, and the equality arm still permits requesting the base directory. `full` is still the sole value passed to `http.ServeFile`, so no downstream call reverts to the unvalidated input.

## Behaviour changes

- A request that previously reached `uploads-backup` (or any other sibling directory sharing the `uploads` prefix, e.g. `uploads2`) now gets `403 invalid file path` instead of the file contents. This is the vulnerability closing, not a regression.
- No change for any request that resolves to a real file inside `/srv/app/uploads`, including the base directory itself (`file=.` or empty-after-join cases) and nested paths (`file=sub/dir/name.txt`).
- Error responses, status codes, and the `http.ServeFile` call (headers, range handling, 404-on-missing behavior) are unchanged.

**Checks run**: `gofmt -l` (clean), `go vet ./...` (clean, both native Windows and cross-compiled `GOOS=linux`), `go build` (clean, both targets). A table-driven test simulating the fixed containment logic against Unix path semantics (the deployment target, given the hardcoded `/srv/app/uploads` path) passed: a legitimate nested file is allowed, `../uploads-backup/secret.txt` and `../../etc/passwd` are rejected, and the base directory itself remains permitted.
