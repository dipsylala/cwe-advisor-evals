## Verdict

**Confirmed.** The code is vulnerable to path traversal via a malicious filename. An attacker can upload a file with a name like `../../../etc/passwd` or `../../webroot/index.html`, writing arbitrary files outside the intended upload directory despite the `Content-Type` validation.

## Source

Line 51–53:
```
destPath := filepath.Join(uploadDir, fileHeader.Filename)
// SAST FINDING: CWE-434 (Unrestricted Upload of File with Dangerous Type) reported here. Sink is the next statement.
dest, err := os.Create(destPath)
```

The vulnerability: `fileHeader.Filename` is not validated. The client controls this value, and `filepath.Join()` preserves path traversal sequences like `../`. Even though `Content-Type` is validated, it does not prevent filename-based attacks because `Content-Type` is client-controllable and orthogonal to path traversal.

## Fix

Replace line 51 with:
```go
destPath := filepath.Join(uploadDir, filepath.Base(fileHeader.Filename))
```

This extracts only the filename component, stripping directory separators and traversal sequences. An attacker providing `../../../etc/passwd` will have only `passwd` used as the filename, keeping the file confined to `uploadDir`.

## Explanation

**Why this works:** `filepath.Base()` returns only the final path element, discarding all directory components. A filename like `../../../etc/passwd` becomes `passwd`; `foo/bar.txt` becomes `bar.txt`. This ensures the resulting path is always `uploadDir/filename`, never outside the intended directory.

**Defense-in-depth:** The Content-Type check is a good first layer, but it alone is insufficient against filename-based attacks. Validating the filename by extracting its basename and rejecting names with null bytes or other dangerous characters (e.g., with a regex like `[^\w\-.]`) provides additional hardening. However, using `filepath.Base()` is the primary fix that closes the path traversal sink itself.
