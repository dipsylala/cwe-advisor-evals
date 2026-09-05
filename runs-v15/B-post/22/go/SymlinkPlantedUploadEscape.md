## Verdict

exploitable

## Source

`requestedName` parameter from function caller (line 11)

## Fix

**Vulnerable code (line 20):**
```go
return os.ReadFile(full)
```

**Fixed code (replace lines 19-20):**
```go
	// Verify the resolved path is a regular file, not a symlink
	fi, err := os.Lstat(full)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, os.ErrPermission
	}

	return os.ReadFile(full)
```

## Explanation

The original code validates that the canonicalized path stays within the uploads directory, but does not check for symlinks. An attacker can plant a symlink inside the uploads directory pointing to an arbitrary file outside it. The path validation passes because the symlink itself is within the directory, but `os.ReadFile` follows the symlink and reads the target file outside the restricted directory. The fix adds an `os.Lstat` call to verify the path points to a regular file, not a symlink. `Lstat` does not follow symlinks, so a planted symlink will be detected as non-regular and rejected with `os.ErrPermission`, preventing traversal through symlinks to files outside the base directory.

## Behaviour changes

- Added `os.Lstat` check to verify file is regular type (not symlink, directory, device, etc.) - prevents symlink-based directory escape
- Error handling: now returns error immediately if `Lstat` fails (file not found, permission denied, etc.) instead of reaching `ReadFile`
- Added rejection of non-regular files with `os.ErrPermission` to match the existing error handling pattern
- Return type and contract preserved: still returns `[]byte` and `error`, still rejects access with same error type as validation failure
