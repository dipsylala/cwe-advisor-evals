## Verdict

Exploitable. The path traversal is unmitigated — a user can supply traversal sequences like `../../../etc/passwd` to escape the intended directory.

## Source

Line 10: `const fileName = req.query.file;` — untrusted user input from HTTP query parameter.

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

  const targetPath = path.join(REPORTS_DIR, fileName);

  // Canonicalize and verify path containment
  let baseDir, realPath;
  try {
    baseDir = fs.realpathSync.native(REPORTS_DIR);
    realPath = fs.realpathSync.native(targetPath);
  } catch (e) {
    return res.status(404).send('Report not found');
  }

  // Reject if the resolved path escapes the base directory
  const relative = path.relative(baseDir, realPath);
  if (relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) {
    return res.status(403).send('Access denied');
  }

  fs.readFile(realPath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).send('Report not found');
    }
    res.type('text/plain').send(data);
  });
});

module.exports = router;
```

## Explanation

The original code constructs a file path by joining the base directory with user input using `path.join()`, then passes it directly to `fs.readFile()`. This is vulnerable because `path.join()` does not validate that the result stays within the intended directory — a user can supply `../` sequences to traverse out and access arbitrary files (e.g., `/etc/passwd`).

The fix canonicalizes both the base directory and the requested file path using `fs.realpathSync.native()`, which resolves symlinks and relative path segments (`.` and `..`) to their true filesystem locations. After canonicalization, it uses `path.relative()` to verify the resolved file path remains within the base directory. If the path escapes (indicated by the relative path starting with `..` or being absolute), the request is rejected with a 403 Forbidden response. This pattern prevents traversal via `../` sequences, symlink escape attempts, and absolute paths.

The fix preserves the original callback-based contract of `fs.readFile()` and maintains the same error-handling flow (404 on file not found).

## Behaviour changes

- Requests for files outside the `REPORTS_DIR` are now rejected with HTTP 403 instead of potentially succeeding.
- Symlinks pointing outside `REPORTS_DIR` are now rejected with HTTP 403.
- Absolute paths in the `file` parameter are now rejected with HTTP 403.
- Exceptions from `fs.realpathSync.native()` (e.g., ENOENT, EACCES) are caught and return 404; the application does not crash.
- Successful reads of legitimate files within `REPORTS_DIR` are unaffected.
