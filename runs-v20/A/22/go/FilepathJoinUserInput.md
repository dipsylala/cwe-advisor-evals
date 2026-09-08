## Verdict

Confirmed. The `file` query parameter is attacker-controlled and is joined onto `docsRoot` with `filepath.Join` before being passed to `os.ReadFile`. `filepath.Join` cleans `.` and `..` segments syntactically but does not confine the result to `docsRoot` - a value such as `../../etc/passwd` collapses to a path outside the intended directory, and that path is opened and its contents returned to the client.

## Source

`r.URL.Query().Get("file")` in `downloadHandler` (line 12) - untrusted, attacker-controlled HTTP query parameter, flows unmodified into `filepath.Join(docsRoot, name)` and then into `os.ReadFile(path)`.

## Fix

### File: FilepathJoinUserInput.go

```go
package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const docsRoot = "/var/app/docs"

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	if name == "" {
		http.Error(w, "missing file parameter", http.StatusBadRequest)
		return
	}

	path := filepath.Join(docsRoot, name)

	rel, err := filepath.Rel(docsRoot, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		http.Error(w, "invalid file parameter", http.StatusBadRequest)
		return
	}

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

`filepath.Join` lexically cleans the combined path (resolving `..` segments) but has no notion of a "root" it must stay inside - it will happily produce a path that lands outside `docsRoot` when `name` contains enough `..` segments or an absolute-looking traversal. Passing that path straight to `os.ReadFile` lets a request such as `?file=../../../../etc/passwd` read arbitrary files readable by the process.

The fix keeps the same join (so ordinary filenames and legitimate subdirectory requests behave exactly as before) and adds an explicit containment check with `filepath.Rel(docsRoot, path)`: if the resulting relative path is `..` or begins with `../`, the requested path resolves outside `docsRoot` and the request is rejected with a 400 before any file I/O happens. This is a boundary check on the resolved path rather than a denylist on the input string, so it is not defeated by URL-encoding, alternate traversal sequences, or absolute-path tricks - any `name` value that does not stay under `docsRoot` after joining is caught, and any that does stay under it is served as before.
