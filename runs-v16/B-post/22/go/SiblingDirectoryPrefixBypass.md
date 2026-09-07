## Verdict

CONFIRMED

## Source

```go
candidate := filepath.Join(uploadsDir, requestedFile)
full := filepath.Clean(candidate)

if !strings.HasPrefix(full, uploadsDir) {
    http.Error(w, "invalid file path", http.StatusForbidden)
    return
}

http.ServeFile(w, r, full)
```

## Fix

```go
candidate := filepath.Join(uploadsDir, requestedFile)
full := filepath.Clean(candidate)

if !(full == uploadsDir || strings.HasPrefix(full, uploadsDir+string(filepath.Separator))) {
    http.Error(w, "invalid file path", http.StatusForbidden)
    return
}

http.ServeFile(w, r, full)
```

## Explanation

The original containment check using `strings.HasPrefix(full, uploadsDir)` is vulnerable to a sibling directory bypass. When `uploadsDir = "/srv/app/uploads"`, a request for `"../uploads-backup"` resolves to `/srv/app/uploads-backup`, which passes the string prefix check because `/srv/app/uploads-backup` starts with `/srv/app/uploads` as a substring. This allows access to sibling directories with matching name prefixes.

The fix enforces path-component-aware containment by:

1. Adding equality check: `full == uploadsDir` permits the base directory itself if needed
2. Adding path separator: `uploadsDir+string(filepath.Separator)` ensures we only match files and subdirectories actually inside the base, not siblings with matching prefixes

With this fix, `/srv/app/uploads-backup` no longer matches the prefix check because it does not start with `/srv/app/uploads/` (note the trailing separator). This prevents the sibling directory bypass while still allowing legitimate access to files within the uploads directory.

## Behaviour changes

- **Before**: Requests like `?file=../uploads-backup/file.txt` or similar patterns escaping to a sibling directory with a matching prefix would be incorrectly allowed
- **After**: Containment check properly rejects any path not directly inside the uploadsDir hierarchy by requiring either exact equality or a path-separator-bounded prefix match
