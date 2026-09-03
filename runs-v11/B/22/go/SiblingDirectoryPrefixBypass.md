## Verdict

exploitable

## Source

**Location**: evals/cases/22/go/SiblingDirectoryPrefixBypass/uploads_download.go, lines 20–37

**Data flow**:
- Source (line 20): `requestedFile := r.URL.Query().Get("file")` — user-controlled input from URL query parameter
- Construction (line 26): `candidate := filepath.Join(uploadsDir, requestedFile)` — path joined with untrusted input
- Normalization (line 27): `full := filepath.Clean(candidate)` — syntactically normalized but containment not yet enforced
- Vulnerable validation (line 31): `if !strings.HasPrefix(full, uploadsDir)` — string prefix check without path separator boundary
- Sink (line 37): `http.ServeFile(w, r, full)` — file served to client

**Exploitable path**:
A request with `?file=../uploads-backup` results in `full = "/srv/app/uploads-backup"`, which passes the prefix check because the string "/srv/app/uploads-backup" starts with "/srv/app/uploads", even though the resolved path is in a sibling directory outside the intended `uploadsDir`.

## Fix

**Vulnerable code (line 31)**:
```go
if !strings.HasPrefix(full, uploadsDir) {
    http.Error(w, "invalid file path", http.StatusForbidden)
    return
}
```

**Fixed code**:
```go
if !(full == uploadsDir || strings.HasPrefix(full, uploadsDir+string(filepath.Separator))) {
    http.Error(w, "invalid file path", http.StatusForbidden)
    return
}
```

## Explanation

The fix adds a path separator (`/` on Unix) to the base directory when performing the prefix check. This ensures that sibling directories like `/srv/app/uploads-backup` do not pass the containment validation. The check now verifies either exact equality with the base directory or that the full path is inside the base directory as a proper subdirectory (i.e., the next character after the base directory must be the separator). This eliminates the string-prefix bypass while preserving the ability to serve files directly from `uploadsDir` itself and any of its subdirectories.

## Behaviour changes

**Preserved behavior**: The fixed code maintains the same return type, error response, and file-serving logic. The containment check still runs at the same location and rejects invalid paths in the same way.

**No functional regressions**: The change only affects what is accepted by the validation gate. Valid paths that passed before (files within `uploadsDir` and its subdirectories) continue to pass. Only paths that were incorrectly accepted before (sibling directories) are now rejected, which is the intended security fix.
