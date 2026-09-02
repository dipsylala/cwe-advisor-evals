## Verdict
Path traversal vulnerability confirmed. Line 19's `fs.readFile(targetPath)` is reachable with an attacker-controlled file path that may escape the intended `REPORTS_DIR` directory via sequences like `../../etc/passwd`.

## Source
The vulnerability originates from `req.query.file` (line 10), which is user-controlled input. It flows through `path.join(REPORTS_DIR, fileName)` (line 16) without validation and reaches the sink at `fs.readFile(targetPath)` (line 19). While `path.join()` normalizes paths, it does not prevent traversal outside the base directory when the filename parameter contains `..`.

## Fix
Resolve both the base directory and target path to absolute paths, then verify that the resolved target remains within the base directory before reading:

```javascript
const express = require('express');
const fs = require('fs');
const path = require('path');

const router = express.Router();
const REPORTS_DIR = path.join(__dirname, 'reports');

router.get('/reports/download', (req, res) => {
  const fileName = req.query.file;

  if (!fileName) {
    return res.status(400).send('file query parameter is required');
  }

  const targetPath = path.join(REPORTS_DIR, fileName);
  const resolvedTargetPath = path.resolve(targetPath);
  const resolvedBaseDir = path.resolve(REPORTS_DIR);

  // Verify the resolved path stays within the allowed directory
  if (!resolvedTargetPath.startsWith(resolvedBaseDir + path.sep) && resolvedTargetPath !== resolvedBaseDir) {
    return res.status(403).send('Access denied');
  }

  fs.readFile(resolvedTargetPath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).send('Report not found');
    }
    res.type('text/plain').send(data);
  });
});

module.exports = router;
```

## Explanation
The fix uses `path.resolve()` to convert both paths to absolute form, eliminating ambiguity from `.` and `..` segments. The guard on line 21–23 rejects any resolved path that does not start with the base directory path (prefixed with the platform-specific separator) or exactly equal the base directory itself. This prevents directory-escape attacks: `fileName = '../../etc/passwd'` would produce a `resolvedTargetPath` outside `resolvedBaseDir`, triggering the 403 rejection before `fs.readFile()` executes. The check is placed before the file operation, blocking the sink entirely when a path-traversal attempt is detected.
