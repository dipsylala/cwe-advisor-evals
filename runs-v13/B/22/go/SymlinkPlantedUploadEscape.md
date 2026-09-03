## Verdict
exploitable

## Source
Untrusted parameter `requestedName` (user-supplied filename) passed to `ReadUploadedFile()`. An attacker can supply the name of a symlink within the permitted uploads directory that points to a restricted file outside it.

## Fix

**Vulnerable code:**
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

	// Resolve symlinks to detect escapes before validating containment
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil, os.ErrPermission
	}

	if resolved != uploadsDir && !strings.HasPrefix(resolved, uploadsDir+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}

	return os.ReadFile(resolved)
}
```

## Explanation
The original code validates that a path stays within `uploadsDir` by checking the constructed but unresolved path. However, the validation occurs before symlink resolution: if the path contains a symlink pointing outside the permitted directory, the check passes because the symlink itself is within the directory, but `os.ReadFile()` then follows that symlink and reads the target file outside the boundary. The fix calls `filepath.EvalSymlinks()` to resolve all symlinks and relative path components to their absolute targets before performing the containment check. This ensures that the check validates the actual file being accessed, not just the symlink's location. If EvalSymlinks fails (broken symlink, unresolved path, or permission denied), the function rejects the request with the same error signal as the original.

## Behaviour changes
EvalSymlinks may fail if the target path does not exist or cannot be resolved (e.g. broken symlink, permission denied on intermediate directories). The original code would attempt os.ReadFile on the unresolved path and return its error. The fixed code treats EvalSymlinks failures the same way—returning os.ErrPermission—making the function stricter: broken or inaccessible symlinks are now rejected immediately rather than deferred to the read operation. This is the correct behaviour, as a symlink that cannot be validated should not be followed.
