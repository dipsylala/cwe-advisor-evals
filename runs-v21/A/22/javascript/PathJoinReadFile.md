## Verdict

CWE-22 Path Traversal vulnerability confirmed. The user-supplied `fileName` parameter is used directly in `path.join()` without validation, allowing directory traversal attacks (e.g., `../../etc/passwd`) to read files outside the intended `REPORTS_DIR` directory.

## Source

Line 16 joins the untrusted `fileName` from `req.query.file` (line 10) with `REPORTS_DIR` using `path.join()`. Since `path.join()` normalizes `../` sequences without restricting them, a malicious input can escape the intended directory boundary before being passed to `fs.readFile()` at line 19.

## Fix

### File: PathJoinReadFile.js

```javascript
const express = require('express');
const fs = require('fs');
const path = require('path');

const router = express.Router();
const REPORTS_DIR = path.resolve(__dirname, 'reports');

// Streams a generated report back to the caller by file name.
router.get('/reports/download', (req, res) => {
  const fileName = req.query.file;

  if (!fileName) {
    return res.status(400).send('file query parameter is required');
  }

  // Prevent absolute paths
  if (path.isAbsolute(fileName)) {
    return res.status(400).send('Invalid file path');
  }

  const targetPath = path.resolve(REPORTS_DIR, fileName);
  const relativePath = path.relative(REPORTS_DIR, targetPath);

  // Prevent path traversal by checking if relative path escapes the directory
  if (relativePath.startsWith('..')) {
    return res.status(400).send('Invalid file path');
  }

  // SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
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

The fix implements containment validation before file access:

1. **Absolute path check**: `path.isAbsolute(fileName)` rejects paths that start with `/` or drive letters (e.g., `/etc/passwd` on Unix or `C:\Windows` on Windows), which would ignore the base directory entirely.

2. **Path resolution and normalization**: `path.resolve(REPORTS_DIR, fileName)` normalizes both the base directory and the user-supplied input to absolute paths, resolving `..` sequences to their actual paths.

3. **Containment validation**: `path.relative(REPORTS_DIR, targetPath)` computes the relative path from the base directory to the resolved target. If this relative path starts with `..`, it means the target is outside the allowed directory and the request is rejected.

This approach is platform-independent (works on Windows and Unix), handles all path traversal encoding methods, and allows legitimate relative paths (e.g., `subdir/file.txt`) while blocking all escape attempts.
