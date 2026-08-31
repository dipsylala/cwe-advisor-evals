## Verdict
Path traversal vulnerability confirmed. `path.join()` does not prevent directory escape via `../` sequences in the user-supplied filename.

## Source
Line 10-16: User input `fileName` from `req.query.file` is passed to `path.join(REPORTS_DIR, fileName)` without validation. An attacker can supply `../../../etc/passwd` or similar sequences to read files outside the intended reports directory.

Example attack: GET `/reports/download?file=../../../etc/passwd` resolves to `/etc/passwd` instead of a file in REPORTS_DIR.

## Fix
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

  const targetPath = path.resolve(REPORTS_DIR, fileName);
  const basePath = path.resolve(REPORTS_DIR);

  // Verify the resolved path stays within the base directory
  if (!targetPath.startsWith(basePath + path.sep) && targetPath !== basePath) {
    return res.status(400).send('Invalid file path');
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
The fix uses `path.resolve()` to normalize both the base directory and the target path to absolute paths, then verifies the target is within the base directory using a startsWith check. This prevents `../` and similar sequences from escaping the intended directory. The check handles both normal files (requiring the path separator after the base) and the edge case where the target equals the base directory itself.
