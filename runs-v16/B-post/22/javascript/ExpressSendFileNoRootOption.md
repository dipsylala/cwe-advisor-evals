## Verdict

Valid. Path traversal is exploitable through `../` sequences in the `file` query parameter.

## Source

`req.query.file` — user-supplied query parameter, decoded by Express before reaching application code.

## Fix

Validate that the filename is a simple filename without path components, then use `res.sendFile()` with the `root` option. Express validates that the resolved path stays within the specified directory.

```javascript
const requestedFile = req.query.file;

if (!requestedFile) {
  return res.status(400).send('Missing file parameter');
}

// Validate that requestedFile is just a filename, not a path with traversal
if (path.basename(requestedFile) !== requestedFile) {
  return res.status(400).send('Invalid file parameter');
}

// Use res.sendFile with root option for containment validation
res.sendFile(requestedFile, { root: reportsDir });
```

## Explanation

The original code constructs a file path using `path.join(reportsDir, requestedFile)` but does not validate that the result stays within `reportsDir`. An attacker passing `../../../etc/passwd` escapes the intended directory and accesses arbitrary files the server process can read.

The fix applies two controls: First, `path.basename(requestedFile) !== requestedFile` rejects any input containing path separators or relative components like `..` — a canonical check that ensures the input is a simple filename. Second, passing `root: reportsDir` to `res.sendFile()` invokes Express's built-in containment validation. Express documents that with `root` set, it resolves the path and verifies the result stays within the specified root; without `root`, no such validation occurs and absolute paths are required. This combines the framework's own mechanism (preferable to hand-written path checking) with an input validation gate.

## Behaviour changes

- Requests with filenames containing path separators (`/`, `\`) or relative components (`..`) now receive HTTP 400 instead of attempting to resolve outside the directory.
- File access is enforced at both the validation layer (basename check) and the framework layer (`root` option).
- The error response improves auditability by explicitly rejecting malformed requests rather than silently serving unintended files or returning 404.
