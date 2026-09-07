## Verdict

Exploitable. The code validates path containment using string prefix comparison but does not resolve symlinks. An attacker can plant a symlink inside the allowed directory that points outside it, causing the file operation to escape the intended boundary.

## Source

`requestedName` parameter to `ReadUploadedFile()`, user-supplied input from an upload request.

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

	// Resolve symlinks to prevent traversal through planted links
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil, os.ErrPermission
	}

	// Verify the resolved path remains within the base directory
	if resolved != uploadsDir && !strings.HasPrefix(resolved, uploadsDir+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}

	return os.ReadFile(resolved)
}
```

## Explanation

The vulnerability: `filepath.Clean()` and the string prefix check prevent basic path traversal (e.g., `../../../etc/passwd`), but they do not resolve symlinks. An attacker can create a symlink inside `/var/app-data/uploads/` pointing to any file on the system (e.g., `uploads/secret` → `/etc/passwd`), and the code will follow it when `os.ReadFile()` is called, reading files outside the intended directory.

The fix adds `filepath.EvalSymlinks()` after the initial boundary validation to resolve all symlinks to their targets. It then re-applies the same boundary check to the resolved path. If the symlink points outside the allowed directory or if the symlink cannot be resolved (broken or unreadable), the function returns `os.ErrPermission` without attempting to read. This closes the symlink-based escape route while preserving the original sink contract: `ReadUploadedFile` still returns `([]byte, error)` with the same semantics.

## Behaviour changes

- **New error path**: If `filepath.EvalSymlinks()` fails (broken symlink, permission denied, etc.), the function returns `os.ErrPermission` instead of proceeding. This is intentional fail-closed behaviour per the guidance; it prevents reading through unresolvable symlinks.
- **Boundary check applied twice**: The code now validates both the input path and the resolved symlink target against the directory boundary. This is necessary because the symlink target might be outside the boundary even if the symlink itself is inside.
- **File read uses resolved path**: `os.ReadFile()` is called on the resolved path rather than the original input, ensuring the file actually read is the symlink target, not the symlink itself.
