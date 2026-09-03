## Verdict

CWE-22 confirmed. The route passes an unsanitized user-supplied filename directly to `res.sendFile()` without using the `root` option, allowing path traversal attacks.

## Source

Line 22, `res.sendFile(reportPath)`. The `reportPath` is constructed by joining an untrusted query parameter (`req.query.file`) with the reports directory. An attacker can inject path traversal sequences (e.g., `file=../../etc/passwd`) to access files outside the intended directory because `path.join()` normalizes the path but does not restrict it to a specific base directory.

## Fix

Use the `root` option in `sendFile()` to confine file serving to the reports directory:

```javascript
router.get('/reports/download', (req, res) => {
  const requestedFile = req.query.file;

  if (!requestedFile) {
    return res.status(400).send('Missing file parameter');
  }

  res.sendFile(requestedFile, { root: reportsDir });
});
```

Remove the manual `path.join()` construction and pass only the filename. The `root` option tells Express to restrict all file access to paths within `reportsDir`; any attempt to escape that boundary (e.g., with `../` sequences) will cause `sendFile()` to reject the request with a 403 Forbidden response.

## Explanation

The `root` option in Express's `sendFile()` enforces a security boundary. When specified, Express resolves the requested file relative to the root directory and verifies that the resulting canonical path still lies within that root. Path traversal attempts are rejected before any file I/O occurs. This is the designed mechanism for safely serving user-selected files from a constrained directory without manual path validation logic.
