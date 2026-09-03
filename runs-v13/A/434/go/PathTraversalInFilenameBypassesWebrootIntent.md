## Verdict

Real: The code constructs a file path by joining a fixed upload directory with a user-supplied filename without validating that the resulting path remains within the intended directory. An attacker can supply a filename with path traversal sequences (e.g., `../../etc/passwd`) or an absolute path, causing files to be written outside the webroot.

## Source

Line 51-53:
```go
destPath := filepath.Join(uploadDir, fileHeader.Filename)
// SAST FINDING: CWE-434
dest, err := os.Create(destPath)
```

The vulnerability is that `fileHeader.Filename` is user-controlled and can contain path traversal sequences. While `filepath.Join` performs some normalization, it does not prevent path traversal when the second argument starts with `../` or is an absolute path.

## Fix

Extract only the base filename component before joining it with the upload directory. Replace line 51 with:

```go
destPath := filepath.Join(uploadDir, filepath.Base(fileHeader.Filename))
```

This ensures that only the filename portion (without any directory separators) is used, preventing traversal attacks. The `filepath.Base()` function returns only the final path element, stripping any directory path components from the user-supplied value.

## Explanation

The root cause is that user-supplied filenames can contain path traversal characters. The content-type validation on line 46 prevents dangerous file types but does nothing to restrict where files are written. An attacker could upload a file named `../../../../etc/shadow` (or similar), and depending on process permissions, write or overwrite sensitive files outside the intended attachment directory.

Using `filepath.Base()` on the filename ensures the result is always a simple filename with no path separators, making path traversal impossible. The resolved path will always remain within `uploadDir` regardless of what characters the attacker includes in their filename.
