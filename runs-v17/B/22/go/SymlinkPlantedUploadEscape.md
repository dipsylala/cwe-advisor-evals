## Verdict

CONFIRMED - Symlink traversal escape vulnerability in path containment validation.

## Source

User-controlled input `requestedName` flows from function parameter into `filepath.Join()` and downstream to `os.ReadFile()`. The data flow is:

1. `requestedName` (untrusted parameter)
2. `filepath.Join(uploadsDir, requestedName)` → constructs full path
3. `filepath.Clean(full)` → normalizes syntax only, does not prevent symlink escape
4. Containment validation with `strings.HasPrefix()` → checks final path is within base directory
5. `os.ReadFile(full)` (sink) → VULNERABLE: follows symlinks

## Explanation

The validation correctly prevents path traversal via `../` sequences and ensures the canonicalized path stays within `/var/app-data/uploads`. However, the check is bypassed by symlinks planted inside the uploads directory. An attacker can create a symlink (e.g., `link -> /etc/passwd`) inside the served directory, request it via `ReadUploadedFile("link")`, and read arbitrary files on the filesystem.

The containment check passes because the symlink's own path (`/var/app-data/uploads/link`) is within the directory. The `os.ReadFile()` call then follows the symlink to the real target (`/etc/passwd`), exposing files outside the intended directory.

Per CWE-22 Go guidance, the fix rejects non-regular files (symlinks, directories, devices) using `os.Lstat()` before opening. `os.Lstat()` does not follow symlinks, so the check correctly identifies and rejects the link itself. Files that pass the check are guaranteed to be regular files within the allowed directory.

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

	// Reject symlinks and other non-regular files to prevent escape via planted links
	info, err := os.Lstat(full)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, os.ErrPermission
	}

	return os.ReadFile(full)
}
```

## Behaviour changes

- **Error handling**: `os.Lstat()` is called before `os.ReadFile()`. File-not-found errors from `Lstat` are propagated immediately (e.g., `io.EOF`, permission errors). Existing callers that handle `os.ReadFile()` errors already handle these cases.
- **Non-regular file rejection**: Requests for symlinks, directories, sockets, or device files now return `os.ErrPermission` instead of `os.ErrInvalid` or similar. Callers expecting `ErrPermission` for access denial are already compatible. Callers that differentiate error types should treat `ErrPermission` as the canonical access-denied response per Go convention.
- **Performance**: Minimal impact—adds one `Lstat()` syscall per read, which is the standard cost of symlink-safety checks.

The fix preserves the sink's contract: returns `[]byte` and `error` on success/failure respectively. No changes to caller-visible behavior except that symlink escapes are now prevented.
