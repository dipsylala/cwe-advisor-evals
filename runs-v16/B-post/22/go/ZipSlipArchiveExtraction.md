## Verdict

exploitable

## Source

`entry.Name` from `archive/zip.File` (untrusted archive content provided by user via multipart upload)

## Fix

Add validation with `filepath.IsLocal()` before using `entry.Name` to construct the destination path.

**Vulnerable code:**
```go
for _, entry := range reader.File {
    destPath := filepath.Join(extractDir, entry.Name)
    // ... uses destPath in os.Create and os.MkdirAll
```

**Fixed code:**
```go
for _, entry := range reader.File {
    // Reject absolute paths and path traversal attempts
    if !filepath.IsLocal(entry.Name) {
        return fmt.Errorf("invalid entry name: %s", entry.Name)
    }

    destPath := filepath.Join(extractDir, entry.Name)
    // ... uses destPath in os.Create and os.MkdirAll
```

## Explanation

The original code constructs destination paths using `filepath.Join(extractDir, entry.Name)` without validating that `entry.Name` does not contain path traversal sequences. An archive entry with a name like `"../../etc/passwd"` or an absolute path would result in files being created outside the intended `extractDir`. The fix uses `filepath.IsLocal()` (available since Go 1.20) to reject absolute paths and path components that escape the base directory before computing the destination path. This ensures all extracted files remain within the base extraction directory, eliminating the Zip Slip vulnerability.

## Behaviour changes

- A validation check is added that rejects archive entries with absolute paths or path traversal sequences before any filesystem operations are attempted
- Extraction now returns an error when an invalid entry name is encountered, preventing silent failures or unexpected file creation outside the base directory
- The error message includes the rejected entry name for debugging and logging purposes

All other behavior is preserved: legitimate file entries are extracted with their relative directory structure intact within the base directory, and the function's overall error handling and cleanup (closing file handles, removing temp files) remains unchanged.
