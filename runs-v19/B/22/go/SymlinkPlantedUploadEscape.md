## Verdict

Exploitable. The code validates that user-controlled path input stays within the intended directory through nominal path containment checks, but does not account for symlink-based escape. An attacker can plant a symlink in the uploads directory pointing to a file outside the boundary; the containment check passes because it only inspects the nominal path, but `os.ReadFile` follows the symlink to the attacker-controlled target, enabling arbitrary file read.

## Source

`requestedName` parameter - untrusted user input from an HTTP request or similar external source.

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

	// Resolve symlinks to prevent escape via planted symlinks
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil, os.ErrPermission
	}

	// Verify the resolved path is still within the uploads directory
	if resolved != uploadsDir && !strings.HasPrefix(resolved, uploadsDir+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}

	return os.ReadFile(resolved)
}
```

## Explanation

The fix adds symlink resolution before the file operation. After the initial nominal containment check passes, `filepath.EvalSymlinks` resolves all symlinks in the path to their actual targets, following the guidance in CWE-22/go that symlinks must be resolved when the directory may contain attacker-controlled links. The resolved absolute path is then verified against the same containment boundary to ensure the target directory still lies within the uploads directory. Any error from symlink resolution (including a broken symlink or permission issue) is treated as permission denied, failing closed. Only after both containment checks pass does the code use the resolved path for the file read. This prevents an attacker from escaping the uploads directory by planting a symlink within it.

## Behaviour changes

- Added call to `filepath.EvalSymlinks(full)` before the file operation, which resolves all symlinks and returns the canonical target path. On error (broken link, permission denied, or any resolution failure), the function returns `os.ErrPermission` instead of attempting the read.
- Added second containment check comparing the resolved path against the uploads directory, using the same boundary logic as the nominal path check.
- Changed the argument to `os.ReadFile` from the nominal path to the resolved path. This ensures the file operation reads from the actual target rather than following symlinks.
- No change to function signature, return type, or error contract. Legitimate files within the directory read identically; symlinks inside the boundary that point outside it now correctly return permission denied instead of leaking external files.
