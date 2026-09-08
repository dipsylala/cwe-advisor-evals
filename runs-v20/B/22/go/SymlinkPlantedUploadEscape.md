## Verdict

**exploitable** (CWE-22, Improper Limitation of a Pathname to a Restricted Directory)

- Location: `uploads.go`, line 20 - `os.ReadFile(full)` inside `ReadUploadedFile`.
- Confidence: high.

## Source

- **Source**: `requestedName`, the parameter to `ReadUploadedFile` - attacker-controlled (a request-supplied filename).
- **Flow**: `requestedName` -> `filepath.Join(uploadsDir, requestedName)` -> `filepath.Clean(full)` -> a string-prefix containment check (`full != uploadsDir && !strings.HasPrefix(full, uploadsDir+separator)`) -> **sink**: `os.ReadFile(full)` at line 20.
- **Why it's exploitable despite the check**: the containment check only inspects the syntactic string produced by `Join`/`Clean`. It never resolves symlinks. If an attacker can plant a symlink *inside* `uploadsDir` (e.g. via an earlier upload) whose target points outside the directory, `requestedName` naming that symlink produces a `full` value that is lexically inside `uploadsDir` and passes the prefix check - but `os.ReadFile` follows the symlink at open time and reads the file it points to, outside the restricted directory. `filepath.Clean`/`Join` normalize syntax only; they are not a containment boundary and do not detect symlinks, which is exactly the gap this finding exercises.

## Fix

### File: uploads.go

```go
package downloads

import (
	"os"
)

const uploadsDir = "/var/app-data/uploads"

func ReadUploadedFile(requestedName string) ([]byte, error) {
	root, err := os.OpenRoot(uploadsDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	// SAST FINDING: CWE-22 (Path Traversal) reported here. Sink is the next statement.
	return root.ReadFile(requestedName)
}
```

## Explanation

The fix replaces the manual `filepath.Join` + `filepath.Clean` + string-prefix check with Go 1.24+'s `os.OpenRoot`/`os.Root`, which the CWE-22 Go guidance names as the preferred traversal-resistant primitive. `os.OpenRoot(uploadsDir)` opens a handle scoped to that directory; `root.ReadFile(requestedName)` then resolves `requestedName` relative to that root and, per its documented contract, follows symlinks only when their target stays inside the root - a symlink (or a `..`/absolute-path sequence) that would resolve outside the root directory is rejected with an error instead of being followed. This closes the exact gap the original code had: a lexical containment check on a string that never accounted for what a symlink node actually points to. Because `os.Root` performs the join, clean, and containment/symlink enforcement together against the live filesystem, there is no separate "canonicalize then compare" step to get out of sync with the actual read.

## Behaviour changes

- **Error type/value on a rejected path changed.** The original code returned the sentinel `os.ErrPermission` when the string-prefix check failed. The fixed code instead returns whatever `os.Root` reports for an escaping name - observed as a `*fs.PathError`/`*os.PathError` wrapping `"path escapes from parent"` - not `os.ErrPermission`. A caller that does `errors.Is(err, os.ErrPermission)` specifically to detect a rejected traversal attempt will no longer match; a caller that only checks `err != nil` (or uses `os.IsNotExist` for a genuinely missing file, which still works the same way) is unaffected. This is a direct, necessary consequence of moving containment enforcement into `os.Root` rather than a hand-rolled check, and is not preservable without reintroducing the vulnerable pattern.
- **Imports reduced.** `path/filepath` and `strings` are no longer used and were removed; no new import was needed beyond the already-imported `os` package (`os.OpenRoot` and `(*os.Root).ReadFile` are part of the standard library `os` package as of Go 1.24, verified via `go doc os.OpenRoot` / `go doc os.Root` against the locally installed Go 1.25.5 toolchain).
- **Return type and success-path output unchanged.** The function signature (`([]byte, error)`) and the bytes returned for a legitimately-contained file are identical to before; only the rejection path's concrete error differs, as noted above. Nothing the original code discarded is now surfaced, and no previously-implicit argument was given a new value.
- **Verification performed**: copied the fixed file into an isolated scratch module (`go.mod` requiring `go 1.24`) outside the repository/case directory and ran `go build ./...` and `go vet ./...` against the local Go 1.25.5 toolchain - both passed with no diagnostics. A functional scratch test was also run against the fixed logic: reading a legitimate in-root file succeeded and returned its contents; a relative-traversal argument (`../secret/secret.txt`) and an absolute-path argument (`/etc/passwd`) were both rejected with `"path escapes from parent"`. A direct symlink-escape repro (planting a symlink inside the root pointing to a file outside it, then reading it by name) could not be executed in this sandbox because creating a filesystem symlink required a Windows privilege the test process did not hold ("A required privilege is not held by the client"); that specific case is covered instead by `os.Root`'s documented contract - "Methods on Root will follow symbolic links, but symbolic links may not reference a location outside the root" - rather than by a local repro here.
- **Assumption**: no `go.mod` accompanied the case file, so the target Go version is unknown. The fix assumes the project can adopt Go 1.24+ (available toolchain here is 1.25.5), since the language guidance names `os.OpenRoot`/`os.Root` as the preferred fix for exactly this symlink-escape scenario. If the real codebase must remain on an older Go version, the fallback from the same guidance is to resolve both `uploadsDir` and the candidate path with `filepath.EvalSymlinks` before the containment comparison, and use the resolved path for the read, failing closed if either resolution errors.
