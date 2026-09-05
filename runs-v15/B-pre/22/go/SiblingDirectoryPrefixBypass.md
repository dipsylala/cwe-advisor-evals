## Verdict

The code is vulnerable to path traversal via sibling directory prefix bypass.

## Source

The vulnerability enters at line 20:
```go
requestedFile := r.URL.Query().Get("file")
```

User-supplied `file` query parameter reaches line 37 as part of the `full` variable without proper containment validation.

## Fix

Replace the containment check at lines 31–34:

**Vulnerable code:**
```go
// Containment check: confirm the cleaned path still lives under
// uploadsDir before serving it back to the client.
if !strings.HasPrefix(full, uploadsDir) {
	http.Error(w, "invalid file path", http.StatusForbidden)
	return
}
```

**Fixed code:**
```go
// Containment check: confirm the cleaned path still lives under
// uploadsDir before serving it back to the client.
// Require either exact match or a path component boundary (separator).
if full != uploadsDir && !strings.HasPrefix(full, uploadsDir+string(filepath.Separator)) {
	http.Error(w, "invalid file path", http.StatusForbidden)
	return
}
```

## Explanation

The original check `strings.HasPrefix(full, uploadsDir)` is insufficient because it does not enforce a directory boundary. A sibling directory like `/srv/app/uploads-backup` would pass the check because the string literally starts with `/srv/app/uploads`. The fixed containment uses two conditions: either the resolved path equals the base directory exactly (`full == uploadsDir`), or it starts with the base directory followed by a path separator (`uploads/`). This prevents sibling directory escape while allowing files within the uploads tree.

## Behaviour changes

The check is now stricter: it rejects paths that bypass the directory boundary using string prefix matching alone. This eliminates the sibling directory attack vector without changing the file-serving behavior for valid paths that resolve inside the uploads directory.
