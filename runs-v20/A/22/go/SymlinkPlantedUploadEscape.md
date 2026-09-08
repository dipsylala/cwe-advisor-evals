## Verdict

Confirmed. The prefix check operates only on the textual path, not on what the filesystem actually resolves it to. If an attacker can plant a symlink inside `uploadsDir` (for example via the upload feature itself, or any other write primitive into that directory) whose target points outside the directory, a request naming that symlink passes the `strings.HasPrefix` check unchanged - the *link's* path is still under `uploadsDir` - but `os.ReadFile` follows the symlink at open time and returns the contents of whatever the link points to, anywhere on disk.

## Source

`requestedName`, the parameter to `ReadUploadedFile`, is attacker-controlled input naming a file inside the uploads directory.

## Fix

### File: uploads.go
```go
package downloads

import (
	"os"
	"path/filepath"
	"strings"
)

const uploadsDir = "/var/app-data/uploads"

func ReadUploadedFile(requestedName string) ([]byte, error) {
	full := filepath.Join(uploadsDir, requestedName)
	full = filepath.Clean(full)

	if full != uploadsDir && !strings.HasPrefix(full, uploadsDir+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}

	// Resolve symlinks on both the base directory and the requested path
	// before trusting the textual prefix check: the check above only proves
	// the *link's* path is inside uploadsDir, not that the file it resolves
	// to is. A symlink planted inside uploadsDir can point anywhere on disk,
	// and os.ReadFile follows it.
	resolvedBase, err := filepath.EvalSymlinks(uploadsDir)
	if err != nil {
		return nil, err
	}
	resolvedFull, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil, err
	}
	if resolvedFull != resolvedBase && !strings.HasPrefix(resolvedFull, resolvedBase+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}

	return os.ReadFile(resolvedFull)
}
```

## Explanation

`filepath.Clean` plus a `strings.HasPrefix` check defeats the classic `../` traversal because it normalizes `..` segments before comparing, but it never touches the filesystem - it reasons entirely about the string. A symlink is a filesystem object, not a path-string pattern: `uploadsDir/evil-link` is a perfectly well-formed path that lives inside `uploadsDir` and satisfies the prefix check, yet when opened it dereferences to whatever target the link stores, which can be any absolute path, including one well outside `uploadsDir` (`/etc/passwd`, another tenant's directory, etc.).

The fix calls `filepath.EvalSymlinks` on both `uploadsDir` and the candidate path, which walks the filesystem and resolves every symlink component (including one at the final path segment) down to the real, canonical path. It also resolves `uploadsDir` itself rather than assuming it is already free of symlinks - if the base directory is reached through a symlink, comparing an unresolved base against a resolved target would produce false rejections or, worse, false acceptances. The containment check is then re-run against these resolved paths, and the file is opened via the resolved path so no further symlink dereference occurs between the check and the read (`os.ReadFile` on an already-fully-resolved path cannot be redirected further). `EvalSymlinks` requires the target to exist, which matches this function's read-existing-file use case; if the file does not exist, the resulting `error` from `EvalSymlinks` propagates naturally instead of a misleading permission error.
