## Verdict

Confirmed. The code validates that the textual path stays within the base directory using string prefix matching, but does not resolve symlinks before opening. An attacker who can plant a symlink inside the uploads directory can escape the containment using that symlink.

## Source

`requestedName` parameter (untrusted user input) flows into `filepath.Join`, is validated against the base directory using a string prefix check, but is not resolved for symlinks before reaching the sink `os.ReadFile(full)` at line 20.

**Vulnerability**: The containment check only examines the textual path representation. If `/var/app-data/uploads/evil-link` is a symlink pointing to `/etc/passwd`, the string-based check sees the path as contained, but `os.ReadFile` follows the symlink and reads the target file outside the intended directory.

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

	// Resolve symlinks to prevent escape
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil, err
	}

	// Re-check containment after resolving symlinks
	if resolved != uploadsDir && !strings.HasPrefix(resolved, uploadsDir+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}

	return os.ReadFile(resolved)
}
```

## Explanation

The fix adds symlink resolution before opening the file. After the initial string-based containment check passes, `filepath.EvalSymlinks(full)` resolves all symlinks in the path to their true targets. If resolution fails (path does not exist or cannot be resolved), the error is returned immediately rather than proceeding with an unresolved path. After resolution succeeds, the same containment check is reapplied to the resolved path to ensure the actual file being read remains within the allowed directory. This prevents an attacker from using a planted symlink to escape the uploads directory and access arbitrary files.

## Behaviour changes

- If the path contains symlinks that resolve to a location outside the base directory, the operation now correctly rejects it instead of allowing the escape.
- If the path does not exist or symlink resolution fails, the function now returns an error instead of proceeding to attempt `os.ReadFile` (which would also fail, but less explicitly).
- For valid paths without symlinks, the function behaves identically: returns the file contents for files within the directory, or `os.ErrPermission` for paths outside it.
