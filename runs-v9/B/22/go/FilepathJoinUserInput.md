## Verdict

Exploitable. CWE-22 (Improper Limitation of a Pathname to a Restricted Directory / Path Traversal), high confidence.

- **Location**: `FilepathJoinUserInput.go`, line 21 (`os.ReadFile(path)`)
- **Source**: `r.URL.Query().Get("file")` (line 12) - the `file` query parameter, fully attacker-controlled
- **Sink**: `os.ReadFile(path)` (line 21)

## Source

`name := r.URL.Query().Get("file")` at line 12. The value is checked only for emptiness (line 13) and then passed straight into `filepath.Join(docsRoot, name)` at line 18 with no traversal or absolute-path check. `filepath.Join` calls `filepath.Clean` on its result, which resolves `..` segments syntactically but does not confine the result to `docsRoot` - a value such as `../../etc/passwd` collapses `/var/app/docs/../../etc/passwd` down to `/etc/passwd`, which then reaches `os.ReadFile` unchecked at line 21.

## Fix

Vulnerable code:

```go
path := filepath.Join(docsRoot, name)

// SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
data, err := os.ReadFile(path)
if err != nil {
	http.Error(w, "not found", http.StatusNotFound)
	return
}
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

	// Reject absolute paths and traversal sequences before they ever reach filepath.Join.
	if filepath.IsAbs(name) || strings.Contains(name, "..") {
		http.Error(w, "invalid file parameter", http.StatusBadRequest)
		return
	}

	base, err := filepath.Abs(docsRoot)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	path := filepath.Join(base, name)

	// Enforce allowlist containment: the joined-and-cleaned result must stay inside base.
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

The fix adds two independent layers before the file is read. First, it rejects any `file` value that is an absolute path (`filepath.IsAbs`) or contains a `..` sequence, closing off the most direct traversal attempts before they ever reach `filepath.Join`. Second - because `filepath.Clean`/`filepath.Join` only normalize path syntax and are not themselves a security boundary - it makes `docsRoot` absolute, joins and cleans the candidate path, and then verifies the result is either equal to the base directory or has the base directory plus a path separator as a prefix. The separator-qualified prefix check prevents a sibling directory (e.g. `/var/app/docs-secret`) from passing a bare string-prefix test, and the explicit equality case still permits the base directory itself. Only after both checks pass does the code proceed to `os.ReadFile`, so no value that could resolve outside `docsRoot` ever reaches the sink.

## Behaviour changes

- A `file` value containing `..` or an absolute path now returns `400 Bad Request` ("invalid file parameter") instead of attempting the read; previously such a value would either succeed (traversal) or fail later with `404 Not Found` depending on what it resolved to. This is the intended effect of closing the weakness.
- A `file` value that resolves (after join and clean) to a path outside `docsRoot` for any other reason also now returns `400 Bad Request` instead of `404 Not Found`. The distinct status code makes rejected/out-of-bounds input distinguishable from a legitimate not-found lookup in logs and client handling.
- Added a fallible `filepath.Abs(docsRoot)` call; on the (practically unreachable, since `docsRoot` is a fixed constant) failure path this returns `500 Internal Server Error`. This does not change behavior for any real input, since `docsRoot` is a hardcoded literal and `filepath.Abs` only fails if `os.Getwd()` fails.
- No change to the success path: a valid `file` value within `docsRoot` still returns the file contents with `Content-Type: application/octet-stream`, unchanged from the original.
- Assumption: Go version is not confirmed, so the fix uses the clean-join-verify-containment pattern rather than Go 1.24+ `os.OpenRoot`/`os.Root`, which the language guidance prefers where available. If the target Go version is confirmed to be 1.24+, `os.OpenRoot(docsRoot)` plus `Root.Open(name)` would be a stronger alternative that also resists symlink-based escapes, which the containment check alone does not address.
