## Verdict

Real vulnerability: CWE-22 symlink escape.

## Source

The parameter `requestedName` is attacker-controlled user input. An attacker who can place files in the uploads directory can create a symlink pointing to files outside the directory (e.g., `/etc/passwd`).

## Fix

Resolve symlinks before the boundary check using `filepath.EvalSymlinks`. The check currently passes because the symlink itself is within the uploads directory, but it fails to account for where the symlink points. Resolving symlinks before validation ensures the security boundary is enforced on the actual target file, not the symlink.

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

	// Resolve symlinks before boundary check to prevent escape
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil, os.ErrPermission
	}
	full = resolved

	if full != uploadsDir && !strings.HasPrefix(full, uploadsDir+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}

	return os.ReadFile(full)
}
```

## Explanation

The vulnerability occurs because `filepath.Clean` only normalizes path syntax (resolving `.` and `..`); it does not resolve symlinks. An attacker who plants a symlink in the uploads directory can point it outside the directory. The boundary check validates the unresolved symlink path (e.g., `/var/app-data/uploads/link`), which is inside the permitted directory, so it passes. When `os.ReadFile` is called with the symlink path, it follows the symlink and reads the external target file.

The fix calls `filepath.EvalSymlinks(full)` before the boundary check. This resolves symlinks to their actual targets. If the symlink points outside the uploads directory, the resolved path fails the containment check and the function rejects it. If `EvalSymlinks` fails (e.g., the symlink is broken), the function also rejects the request, treating any error as an unresolved/untrusted path per the guidance.

## Behaviour changes

- Symlinks pointing outside the uploads directory are rejected instead of followed.
- Broken symlinks are rejected (same as before the fix, `os.ReadFile` would fail, but now earlier in the flow).
- Symlinks to files inside the uploads directory are resolved and validated; the actual target must still be within the directory boundary.
- File reading remains unchanged for regular files that were previously allowed.
