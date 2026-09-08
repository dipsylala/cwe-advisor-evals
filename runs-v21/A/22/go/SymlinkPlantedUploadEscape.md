## Verdict
CONFIRMED

## Source
The vulnerability exists because `filepath.Clean()` normalizes the path string (removing `..` and `.` components) but does not resolve symbolic links. An attacker can plant a symlink file in the uploads directory that points to a file outside the restricted directory. The string-based boundary check using `strings.HasPrefix()` validates the path string itself, not the actual file the symlink points to. When `os.ReadFile()` is called, it follows the symlink and reads an arbitrary file outside `uploadsDir`.

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

	// Resolve symbolic links to prevent path traversal via symlink targets
	realPath, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil, os.ErrPermission
	}

	// Verify the resolved path is within the uploads directory
	if realPath != uploadsDir && !strings.HasPrefix(realPath, uploadsDir+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}

	return os.ReadFile(realPath)
}
```

## Explanation
The fix introduces `filepath.EvalSymlinks()` after the string-based path construction and cleaning. This function resolves all symbolic links in the path, returning the canonical path that points to the actual file on disk. The boundary check then validates the resolved path, ensuring that even if a symlink was planted in the uploads directory, its target must still be within the allowed directory. If `EvalSymlinks()` fails (e.g., broken symlink or permission denied), the function returns `os.ErrPermission`, preventing access. Finally, `os.ReadFile()` is called with the validated real path, guaranteeing the actual file read is within the restricted directory.
