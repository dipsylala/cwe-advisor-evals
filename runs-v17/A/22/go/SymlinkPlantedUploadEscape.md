## Verdict
Confirmed. The path validation using `filepath.Clean` and `strings.HasPrefix` does not account for symlinks. An attacker can plant a symlink in the uploads directory pointing to any file on the system, bypassing the directory boundary check.

## Source
`uploads.go` line 20: `os.ReadFile(full)` is called after validating the path string, but the validation does not resolve symlinks. The check on line 15 passes for symlinks that escape the directory sandbox.

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

	// Resolve symlinks in both the base and target paths to the canonical filesystem location
	realBase, err := filepath.EvalSymlinks(uploadsDir)
	if err != nil {
		return nil, os.ErrPermission
	}

	realFull, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil, os.ErrPermission
	}

	// Verify the canonical path is within the upload directory
	if !strings.HasPrefix(realFull, realBase+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}

	return os.ReadFile(full)
}
```

## Explanation
The fix replaces path string validation with symlink resolution using `filepath.EvalSymlinks`. This converts both the base directory and the requested file path to their canonical filesystem locations, resolving all intermediate symlinks.

The check `strings.HasPrefix(realFull, realBase+string(filepath.Separator))` now verifies that the actual file on disk resides within the actual uploads directory, not just that the path string appears safe. If an attacker plants a symlink like `/var/app-data/uploads/evil` → `/etc/passwd`, `EvalSymlinks` resolves it to `/etc/passwd`, which fails the prefix check and is rejected. Legitimate files within the uploads directory resolve to paths starting with the real base directory and pass validation.
