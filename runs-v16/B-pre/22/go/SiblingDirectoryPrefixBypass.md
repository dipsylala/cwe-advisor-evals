## Verdict

Exploitable. The containment check uses a raw string prefix comparison without path-component awareness, allowing attackers to traverse into sibling directories whose names share a common prefix with the base directory.

## Source

User-supplied file name from HTTP query parameter at line 20: `r.URL.Query().Get("file")`, passed through `filepath.Join` and `filepath.Clean` to construct the candidate path.

## Fix

**Vulnerable code (line 31):**
```go
if !strings.HasPrefix(full, uploadsDir) {
	http.Error(w, "invalid file path", http.StatusForbidden)
	return
}
```

**Fixed code:**
```go
if !(full == uploadsDir || strings.HasPrefix(full, uploadsDir+string(filepath.Separator))) {
	http.Error(w, "invalid file path", http.StatusForbidden)
	return
}
```

## Explanation

The vulnerability arises from a string prefix check that ignores path components. If `uploadsDir` is `/srv/app/uploads`, a raw `HasPrefix` check would accept `/srv/app/uploads-backup/secret` because the string `/srv/app/uploads-backup/secret` starts with the prefix `/srv/app/uploads`, even though it escapes into a sibling directory. The fix requires the checked path to either equal the base directory exactly (for accessing the base itself) or start with the base directory followed by a path separator. This boundary check ensures sibling directories cannot match, since `/srv/app/uploads-backup` does not start with `/srv/app/uploads/`.

## Behaviour changes

None. The fix preserves the intended containment semantics: it still permits any file within the uploads directory (including the directory itself if served) while blocking any path outside it. The fix does not alter return values, discarded output, implicit arguments, or error handling—only the security boundary condition.
