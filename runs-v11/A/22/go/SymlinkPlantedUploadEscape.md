## Verdict
Confirmed. The code validates normalized paths against directory traversal but does not account for symlinks planted within the allowed directory. A symlink pointing outside the directory will pass validation and be followed during file access, allowing unauthorized file reads.

## Source
Line 20 in `ReadUploadedFile()` calls `os.ReadFile(full)` after validating `full` against the directory. The validation checks if the cleaned path is within `uploadsDir`, but `os.ReadFile()` follows symlinks, bypassing the intended restriction if `full` is a symlink pointing outside the allowed directory.

Attack scenario: An attacker creates a symlink at `/var/app-data/uploads/evil-link` → `/etc/passwd`. When `requestedName` is `"evil-link"`, the path validation at line 15 passes (the symlink itself is within `uploadsDir`), but `os.ReadFile()` resolves and follows the symlink to read `/etc/passwd`.

## Fix
Resolve all symlinks before file access and validate the resolved path against the directory:

```go
func ReadUploadedFile(requestedName string) ([]byte, error) {
	full := filepath.Join(uploadsDir, requestedName)
	full = filepath.Clean(full)

	if full != uploadsDir && !strings.HasPrefix(full, uploadsDir+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}

	// Resolve symlinks to get the canonical path
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil, err
	}

	// Verify the resolved path is still within the allowed directory
	if resolved != uploadsDir && !strings.HasPrefix(resolved, uploadsDir+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}

	return os.ReadFile(resolved)
}
```

## Explanation
The fix adds a second path validation after resolving symlinks. `filepath.EvalSymlinks()` returns the absolute canonical path with all symlinks resolved. After resolution, the code re-validates that the target is still within the allowed directory before reading. This prevents symlink-based escapes: even if an attacker plants a symlink within `uploadsDir`, attempting to read a symlink pointing outside will fail the second validation and return `os.ErrPermission`.
