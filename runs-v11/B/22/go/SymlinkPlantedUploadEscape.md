## Verdict

Exploitable

## Source

The `requestedName` parameter is user-controlled input that derives from an attacker-influenced upload request. It reaches the path construction at line 12 via `filepath.Join(uploadsDir, requestedName)`.

## Fix

**Vulnerable code (line 11-20):**
```go
func ReadUploadedFile(requestedName string) ([]byte, error) {
	full := filepath.Join(uploadsDir, requestedName)
	full = filepath.Clean(full)

	if full != uploadsDir && !strings.HasPrefix(full, uploadsDir+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}

	// SAST FINDING: CWE-22 (Path Traversal) reported here. Sink is the next statement.
	return os.ReadFile(full)
}
```

**Fixed code:**
```go
func ReadUploadedFile(requestedName string) ([]byte, error) {
	full := filepath.Join(uploadsDir, requestedName)
	full = filepath.Clean(full)

	// Resolve symlinks to their actual targets before validation
	var err error
	full, err = filepath.EvalSymlinks(full)
	if err != nil {
		return nil, os.ErrPermission
	}

	if full != uploadsDir && !strings.HasPrefix(full, uploadsDir+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}

	return os.ReadFile(full)
}
```

## Explanation

The vulnerability exists because `filepath.Clean()` normalizes path syntax (resolving `.` and `..` sequences) but does not resolve symlinks. An attacker can place a symlink inside the `uploadsDir` that points to a file outside the directory. The current containment check validates that the symlink path itself starts with `uploadsDir`, which it does. However, when `os.ReadFile()` opens the symlink, it follows it and reads the target file outside the intended directory.

The fix adds `filepath.EvalSymlinks()` before the containment validation. This resolves all symlinks in the path to their actual targets. If the resolved path points outside `uploadsDir`, the containment check fails and the function returns an error. If symlink resolution fails (for example, because the target does not exist), the function also fails closed by returning an error, which is the correct behavior for a file read operation.

## Behaviour changes

- **Error handling for non-existent files**: If `requestedName` refers to a non-existent path or a symlink to a non-existent target, `filepath.EvalSymlinks()` now returns an error before `os.ReadFile()` is called. Previously the error would come from `os.ReadFile()` itself. The observable behavior is identical (an error is returned), but it happens one line earlier.
- **Rejection of broken symlinks**: Symlinks pointing to non-existent targets are now rejected by `EvalSymlinks` before the read is attempted. This is a minor behavior change, but appropriate for a security boundary: if a symlink cannot be resolved to a valid target, it should not be read.
- **No change to regular file behavior**: For regular files and valid symlinks within `uploadsDir`, behavior is unchanged.

