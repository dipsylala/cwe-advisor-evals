## Verdict
Path traversal vulnerability confirmed. The string prefix check at line 31 fails to enforce proper path boundaries, allowing access to sibling directories such as `/srv/app/uploads-backup` which share a common prefix with the restricted directory `/srv/app/uploads`.

## Source
Line 20: `requestedFile` is obtained directly from user input without validation.
Line 26-27: Candidate path is constructed and cleaned, but the containment check is insufficient.

## Fix
Replace the containment check with a path-boundary-aware validation:

```go
// Containment check: confirm the cleaned path is strictly under uploadsDir.
// Use HasPrefix with a trailing separator to avoid matching sibling directories
// like "uploads-backup" which share the "uploads" prefix.
if !strings.HasPrefix(full, uploadsDir+"/") {
    http.Error(w, "invalid file path", http.StatusForbidden)
    return
}

http.ServeFile(w, r, full)
```

Alternatively, use `filepath.Rel()` to compute the relative path and verify it does not escape the directory:

```go
rel, err := filepath.Rel(uploadsDir, full)
if err != nil || strings.HasPrefix(rel, "..") {
    http.Error(w, "invalid file path", http.StatusForbidden)
    return
}

http.ServeFile(w, r, full)
```

## Explanation
The original code uses `strings.HasPrefix(full, uploadsDir)` to verify that the resolved path stays within the intended directory. However, string prefix matching is insufficient for path containment.

Example bypass:
- `uploadsDir = "/srv/app/uploads"`
- An attacker requests a sibling directory: `requestedFile = "../uploads-backup/sensitive-file"`
- After `filepath.Join()` and `filepath.Clean()`, `full = "/srv/app/uploads-backup/sensitive-file"`
- The check `strings.HasPrefix("/srv/app/uploads-backup/sensitive-file", "/srv/app/uploads")` returns `true` because the string literally starts with "/srv/app/uploads"
- This allows the attacker to access the sibling directory despite the intended restriction

The fix ensures that the full path either:
1. Equals the upload directory exactly, OR
2. Is a child of the upload directory (starts with `uploadsDir + "/"`)

This prevents string prefix collisions with sibling directories that happen to share a common prefix.
