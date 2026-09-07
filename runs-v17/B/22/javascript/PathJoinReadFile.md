## Verdict

**EXPLOITABLE PATH TRAVERSAL.** The application constructs a file path by joining a user-supplied query parameter with the reports directory without validation. An attacker can supply `file=../../etc/passwd` to read arbitrary files. The fix validates the input and verifies the resolved path stays within the intended directory.

## Source

- **Entry point**: `req.query.file` (line 10) - untrusted HTTP query parameter, decoded by Express
- **Sink**: `fs.readFile(targetPath, ...)` (line 19) - reads the constructed path
- **Path construction**: `path.join(REPORTS_DIR, fileName)` (line 16) - vulnerable because fileName is not validated
- **Vulnerability**: No check that the resolved path remains within REPORTS_DIR; relative path sequences like `../` and absolute paths escape the base directory

## Fix

### File: PathJoinReadFile.js

```javascript
const express = require('express');
const fs = require('fs');
const path = require('path');

const router = express.Router();
const REPORTS_DIR = path.join(__dirname, 'reports');

// Streams a generated report back to the caller by file name.
router.get('/reports/download', (req, res) => {
  const fileName = req.query.file;

  if (!fileName) {
    return res.status(400).send('file query parameter is required');
  }

  // Reject absolute paths and traversal attempts
  if (path.isAbsolute(fileName) || fileName.includes('..')) {
    return res.status(400).send('Invalid file path');
  }

  // Construct the target path and verify it stays within REPORTS_DIR
  const reportsDir = path.resolve(REPORTS_DIR);
  const targetPath = path.resolve(reportsDir, fileName);
  const relative = path.relative(reportsDir, targetPath);

  // Ensure the resolved path stays within the base directory
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    return res.status(400).send('Invalid file path');
  }

  // Safe to read the file
  fs.readFile(targetPath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).send('Report not found');
    }
    res.type('text/plain').send(data);
  });
});

module.exports = router;
```

## Explanation

The fix adds three validation layers before passing the path to `fs.readFile()`:

1. **Reject traversal sequences** (line 16): Check that fileName contains no `..` sequences and is not an absolute path. This stops obvious traversal attempts like `../../etc/passwd` and `/etc/passwd` before they are joined with the base.

2. **Canonicalize paths** (lines 19-21): Use `path.resolve()` on both the base directory and the constructed target to normalize the paths. This collapses `.` and `..` sequences and removes any ambiguity in path representation.

3. **Enforce containment** (lines 23-25): Use `path.relative()` to compute the relative path from the base to the target. If this result starts with `..` or is absolute, the target escaped the base directory. Reject it. This check is path-component-aware and prevents string-prefix bypasses like `REPORTS_DIR=/app/uploads` with `fileName=/app/uploads-secret/file`.

The fix preserves the original error handling and response behavior: legitimate files are read and returned as before, and missing files still trigger the 404 error path (lines 26-32). All validation errors return 400 Bad Request to signal client error.

## Behaviour changes

- **Valid requests unchanged**: Requests for files directly in REPORTS_DIR (e.g., `file=report.txt`) still succeed.
- **New rejection**: Requests containing `..` (e.g., `file=../etc/passwd`), absolute paths (e.g., `file=/etc/passwd`), or paths that would escape the base (e.g., `file=./../../../etc/passwd` after canonicalization) now return 400 Bad Request instead of attempting to read outside REPORTS_DIR.
- **Error response consistent**: Responses for missing files within REPORTS_DIR remain 404 Not Found.
