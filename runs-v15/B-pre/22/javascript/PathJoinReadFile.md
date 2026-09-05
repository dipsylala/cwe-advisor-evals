## Verdict

**Exploitable.** Path traversal is confirmed. The `fileName` parameter from `req.query.file` is concatenated into a file path with `path.join()` without validation, allowing an attacker to escape the `REPORTS_DIR` using sequences like `../`.

## Source

User-supplied query parameter `req.query.file` at line 10. No validation is applied before the value reaches the path construction at line 16.

## Fix

Validate that the resolved path remains within the intended base directory. Resolve both paths to absolute form and verify containment before passing to the file operation sink:

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

  // Resolve paths to absolute form
  const basePath = path.resolve(REPORTS_DIR);
  const targetPath = path.resolve(path.join(REPORTS_DIR, fileName));

  // Verify the resolved path stays within the base directory
  if (!targetPath.startsWith(basePath + path.sep) && targetPath !== basePath) {
    return res.status(404).send('Report not found');
  }

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

The fix resolves both the base directory and the target path to their absolute canonical forms using `path.resolve()`, which normalizes relative path components (including `..` sequences) to their true locations. It then verifies containment by checking that the target path either equals the base path or starts with the base path followed by the path separator. This prevents `../` or absolute path injection from allowing access outside `REPORTS_DIR`.

The error handling preserves the original 404 response for invalid paths, so the attacker cannot distinguish a traversal rejection from a missing file.

## Behaviour changes

- Added path validation that rejects requests where the resolved path escapes the `REPORTS_DIR`. These requests now return 404 instead of potentially serving files outside the intended directory.
- The path passed to `fs.readFile()` is now the canonicalized `targetPath` instead of the joined path, but both resolve to the same file for valid inputs, so the functional behavior for legitimate requests is unchanged.
