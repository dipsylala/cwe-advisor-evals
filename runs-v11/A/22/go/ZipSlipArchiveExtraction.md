## Verdict

Path traversal vulnerability. The code extracts zip archive entries without validating that the resulting paths remain within the intended extraction directory. A malicious archive containing entries like `../../../etc/passwd` can write files outside `extractDir`.

## Source

Line 64: `destPath := filepath.Join(extractDir, entry.Name)`

Line 83: `dst, err := os.Create(destPath)` — sink where the unvalidated path is used.

`entry.Name` comes directly from the zip archive without sanitization.

## Fix

After computing `destPath`, verify it stays within `extractDir` before proceeding:

```go
// Resolve both paths to absolute form to compare them safely.
absExtractDir, err := filepath.Abs(extractDir)
if err != nil {
    return fmt.Errorf("resolve extract dir: %w", err)
}

for _, entry := range reader.File {
    destPath := filepath.Join(extractDir, entry.Name)
    
    // Resolve the destination path and verify it stays within extractDir.
    absDestPath, err := filepath.Abs(destPath)
    if err != nil {
        return fmt.Errorf("resolve path %s: %w", destPath, err)
    }
    
    if !strings.HasPrefix(absDestPath, absExtractDir+string(filepath.Separator)) && absDestPath != absExtractDir {
        return fmt.Errorf("path traversal rejected: %s", entry.Name)
    }
    
    // ... rest of the extraction logic
}
```

Add `"strings"` to the imports.

## Explanation

The vulnerability ("zip slip") occurs because `filepath.Join(extractDir, entry.Name)` does not stop a relative path in `entry.Name` from escaping the directory. For example, `entry.Name = "../../etc/passwd"` joined with `/var/lib/pluginhost/import` produces `/var/lib/pluginhost/etc/passwd`, escaping the intended location.

The fix resolves both paths to their absolute form, then validates that the destination path is either exactly `extractDir` or starts with `extractDir/` (the separator ensures `extractDir-alt` does not match). This ensures every extracted file stays within the intended directory regardless of the archive's contents. Entries attempting escape are rejected with an error rather than silently extracted to an unsafe location.

