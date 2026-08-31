## Verdict

Exploitable. Confidence: high.

`filepath.Join` and the `filepath.Clean` it performs internally only normalize path syntax (collapsing `.`/`..` sequences) - they do not enforce that the result stays inside `docsRoot`. A `file` value such as `../../etc/passwd` survives `filepath.Join(docsRoot, name)` and produces a path outside the intended directory before it reaches `os.ReadFile`. No validation or containment check exists between the source and the sink.

## Source

- **Source**: `r.URL.Query().Get("file")` (line 12, `downloadHandler`) - attacker-controlled HTTP query parameter, assigned to `name`.
- **Flow**: `name` -> `path := filepath.Join(docsRoot, name)` (line 18) - joined and cleaned, but not checked for containment or rejected for `..`/absolute-path content.
- **Sink**: `os.ReadFile(path)` (line 21) - reads and returns the file contents, which are written directly to the HTTP response body.

## Fix

Vulnerable code:

```go
path := filepath.Join(docsRoot, name)

// SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
data, err := os.ReadFile(path)
```

Fixed code:

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

	clean := filepath.Clean(name)
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		http.Error(w, "invalid file parameter", http.StatusBadRequest)
		return
	}

	base, err := filepath.Abs(docsRoot)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	path := filepath.Join(base, clean)
	if path != base && !strings.HasPrefix(path, base+string(filepath.Separator)) {
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

The fix rejects any `file` value that resolves to an absolute path or begins with a `..` traversal element before it is ever joined against the base directory, then joins the cleaned value against an absolute form of `docsRoot` and verifies the resulting path is either equal to that base or a path-component-aware descendant of it (`base+separator` prefix, not a raw string prefix, so a sibling like `/var/app/docs-secret` cannot pass). Only this checked `path` variable - never the original `name` - is used for the subsequent `os.ReadFile` call, so no unvalidated value reaches the sink. No indirect ID-to-path mapping was used because the endpoint serves arbitrary named files from `docsRoot` with no enumerable set of IDs to map from; canonicalize-then-contain is the applicable pattern here per the Go CWE-22 guidance.

## Behaviour changes

- A `file` value containing `..` traversal elements or an absolute path now returns `400 Bad Request` instead of being joined and read; this is the fix itself, not a side effect.
- A `file` value that joins to a path outside `docsRoot` (e.g. via a deep `..` chain that still escapes after cleaning) now returns `400 Bad Request` from the added containment check rather than proceeding to `os.ReadFile`.
- All valid, in-directory `file` values behave exactly as before: same `200` response, same `Content-Type` header, same body, same `404` on a missing file.
- Symlink resolution (`os.Lstat`/`IsRegular()` or Go 1.24+ `os.OpenRoot`) was intentionally not added: nothing in the trace indicates `docsRoot` contains attacker-influenced symlinks, and adding it would reject legitimate symlinked files with no corresponding finding to justify that behaviour change. `os.OpenRoot` is the stronger long-term option if the Go toolchain is confirmed at 1.24+; the containment-check pattern was used instead here since no `go.mod` is present in the case directory to confirm the toolchain version.
