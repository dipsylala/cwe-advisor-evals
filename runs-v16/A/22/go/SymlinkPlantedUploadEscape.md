## Verdict

**Vulnerable.** The code validates that a resolved path stays within the uploads directory but does not account for symlink targets. An attacker can plant a symlink under `/var/app-data/uploads/` pointing outside that directory. The validation passes on the symlink itself, but `os.ReadFile()` follows it and reads the target.

## Source

Line 20: `os.ReadFile(full)` is called after path validation, but the validation does not resolve symlinks. A symlink planted at `uploads/link -> /etc/passwd` will pass the check (the symlink path is within `uploads/`) but leak the target.

## Fix

Resolve symlinks before use and re-validate the resolved path:

```go
func ReadUploadedFile(requestedName string) ([]byte, error) {
	full := filepath.Join(uploadsDir, requestedName)
	full = filepath.Clean(full)

	if full != uploadsDir && !strings.HasPrefix(full, uploadsDir+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}

	// Resolve symlinks to prevent escaping via planted symlinks
	realPath, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil, err
	}

	// Verify the real path is still within the uploads directory
	if realPath != uploadsDir && !strings.HasPrefix(realPath, uploadsDir+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}

	return os.ReadFile(realPath)
}
```

## Explanation

`filepath.EvalSymlinks()` resolves all symlinks in the path to their targets. After resolution, the second path check confirms that the actual file being read is still within the uploads directory. This prevents symlink-plantation attacks where a symlink under the allowed directory points to a sensitive file outside it. The function returns an error if symlink resolution fails (e.g., broken symlink or permissions), which is the correct behavior for this scenario.
