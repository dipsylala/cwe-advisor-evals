## Verdict

Exploitable

## Source

`entry.Name` - untrusted archive entry names from the zip file read at line 63

## Fix

```go
// VULNERABLE CODE (line 64, in extractBundle)
destPath := filepath.Join(extractDir, entry.Name)
```

```go
// FIXED CODE
// Verify the entry name is relative and doesn't escape the extraction directory
if !filepath.IsLocal(entry.Name) {
    return fmt.Errorf("invalid archive entry (possible path traversal): %s", entry.Name)
}

destPath := filepath.Join(extractDir, entry.Name)
```

## Explanation

The vulnerability is a Zip Slip attack: archive entry names are attacker-controlled and reached the file creation sink without validation. An archive could contain entries like `../../../etc/passwd`, which `filepath.Join()` would concatenate with `extractDir` without preventing traversal. The fix validates each entry name with `filepath.IsLocal()` (available in Go 1.20+), which rejects both absolute paths and entries containing `..` path-traversal sequences. This check is applied before the path is joined and passed to `os.Create()`, ensuring all created files remain within the intended `extractDir` boundary.

## Behaviour changes

None. The fix only rejects invalid archive entries that should never have been written to disk. Entries that would have escaped `extractDir` now return a clear error instead of silently writing to arbitrary locations. Legitimate archive entries (relative paths without traversal) are accepted and processed identically to before.
