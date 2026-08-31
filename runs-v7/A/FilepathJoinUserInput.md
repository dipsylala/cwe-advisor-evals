## Verdict
Path traversal vulnerability confirmed. User-supplied filename is joined with a base directory but not validated to remain within that directory, allowing traversal attacks.

## Source
Line 12-18: The `name` parameter is extracted directly from the HTTP query string without validation. It is then joined with `docsRoot` using `filepath.Join()`, which cleans the path but does not prevent directory traversal sequences like `../../etc/passwd`.

Line 21: The unsanitized path is passed to `os.ReadFile()`, allowing files outside the intended directory to be read.

## Fix
Add a validation check after joining the paths to ensure the resolved path remains within the docs root directory:

```go
path := filepath.Join(docsRoot, name)

// Ensure the resolved path does not escape the docs root
rel, err := filepath.Rel(docsRoot, path)
if err != nil || strings.HasPrefix(rel, "..") {
	http.Error(w, "access denied", http.StatusForbidden)
	return
}

data, err := os.ReadFile(path)
```

The `filepath.Rel()` call computes the relative path from `docsRoot` to the joined path. If the result contains `..` components, the requested file is outside the restricted directory and should be rejected.

Also add `"strings"` to the imports if not already present.

## Explanation
`filepath.Join()` normalizes path separators and removes `.` and `..` components, but only within the string it receives. When given `"/var/app/docs"` and `"../../etc/passwd"`, it produces `"/etc/passwd"` by applying the traversal sequences first, then cleaning. This is not a security boundary.

The fix validates the final destination by computing its relative path from the intended root. Any `..` in the result indicates an escape attempt. This is the standard Go pattern for path containment checks and prevents both direct traversal sequences and symlink-based escapes within the filesystem checks.
