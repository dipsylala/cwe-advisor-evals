## Verdict
Path traversal vulnerability confirmed. The code allows an attacker to read arbitrary files by supplying path traversal sequences (e.g., `../../../etc/passwd`) in the `file` query parameter, bypassing the intended `REPORTS_DIR` boundary.

## Source
```javascript
const targetPath = path.join(REPORTS_DIR, fileName);

// SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
fs.readFile(targetPath, 'utf8', (err, data) => {
```

The vulnerability stems from:
- `fileName` is sourced directly from untrusted user input (`req.query.file`)
- `path.join()` does not prevent path traversal sequences; it simply concatenates paths
- No validation ensures `targetPath` remains within `REPORTS_DIR`

## Fix
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

  // Normalize and resolve the full path
  const targetPath = path.resolve(REPORTS_DIR, fileName);
  
  // Ensure the resolved path is within REPORTS_DIR
  if (!targetPath.startsWith(path.resolve(REPORTS_DIR) + path.sep) && targetPath !== path.resolve(REPORTS_DIR)) {
    return res.status(403).send('Access denied');
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
The fix adds a canonicalization and containment check:

1. **`path.resolve()`**: Normalizes the path to its absolute form, resolving `..` and `.` sequences to their true target location, enabling accurate boundary validation.

2. **Containment validation**: Verifies the resolved target path is within `REPORTS_DIR` by checking it starts with the resolved reports directory path followed by a path separator (or equals the directory itself). This prevents escaping the intended directory via traversal sequences.

3. **Early rejection**: Returns 403 Forbidden before attempting file access if the path is out of bounds, stopping the attack before reaching the sink.

The check uses `path.sep` for cross-platform correctness and handles both file and directory paths. With this fix, supplying `file=../../../etc/passwd` results in rejection rather than reading the system file.
