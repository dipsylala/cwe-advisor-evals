## Verdict

The path traversal vulnerability exists because the containment check uses `strings.HasPrefix()` without accounting for directory boundaries. A sibling directory `/srv/app/uploads-backup` shares the same prefix as `/srv/app/uploads`, allowing the check to pass when it should fail.

## Source

Line 31 performs an insufficient containment validation:
```go
if !strings.HasPrefix(full, uploadsDir) {
```

The `uploadsDir` constant is defined without a trailing separator:
```go
const uploadsDir = "/srv/app/uploads"
```

An attacker can request a file path that, after `filepath.Clean()`, resolves to a sibling directory such as `/srv/app/uploads-backup/file`, which passes the prefix check because `/srv/app/uploads-backup` begins with the string `/srv/app/uploads`.

## Fix

Add path separator validation to the containment check to ensure the resolved path is actually contained within the uploads directory, not just sharing a prefix:

```go
if full != uploadsDir && !strings.HasPrefix(full, uploadsDir+string(filepath.Separator)) {
	http.Error(w, "invalid file path", http.StatusForbidden)
	return
}
```

Alternatively, this can be expressed as:

```go
if !strings.HasPrefix(full+string(filepath.Separator), uploadsDir+string(filepath.Separator)) &&
   full != uploadsDir {
	http.Error(w, "invalid file path", http.StatusForbidden)
	return
}
```

## Explanation

The vulnerability arises from prefix matching without respecting path component boundaries. By appending `string(filepath.Separator)` (forward slash on Unix, backslash on Windows) to `uploadsDir`, the check ensures that only paths that are actual children of the uploads directory pass validation.

The condition `full != uploadsDir` allows serving the directory itself if that behavior is intentional; if the handler should only serve files (not directories), remove this part and only check the prefix with the separator.

With this fix:
- `/srv/app/uploads/file.txt` passes (file inside directory)
- `/srv/app/uploads` passes only if the first condition is checked, otherwise fails (the directory itself)
- `/srv/app/uploads-backup/file` fails (sibling directory, no path separator between prefix and suffix)
- `/srv/app/uploads/../other/file` fails (after `filepath.Clean()`, resolves outside the directory)
