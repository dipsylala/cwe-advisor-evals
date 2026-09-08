## Verdict

Confirmed. `fileName` comes from `req.query.file`, an attacker-controlled query parameter, and is passed straight into `path.join(REPORTS_DIR, fileName)`. `path.join` does not strip `../` segments, so a value such as `../../etc/passwd` (or a Windows equivalent / absolute path) resolves outside `REPORTS_DIR`, and the resulting path is passed directly to `fs.readFile`, which streams the target file's contents back in the response.

## Source

`req.query.file` on line 10 (`GET /reports/download?file=...`), flowing unchanged into the `path.join` call on line 16 and then into the `fs.readFile` sink on line 19.

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

  const targetPath = path.join(REPORTS_DIR, fileName);
  const relative = path.relative(REPORTS_DIR, targetPath);

  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    return res.status(400).send('Invalid file name');
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

`path.join` only concatenates and normalizes path segments; it does not confine the result to a base directory, so `..` segments (or a drive-qualified/absolute value on Windows) in `fileName` let the resolved path escape `REPORTS_DIR`. The fix computes `path.relative(REPORTS_DIR, targetPath)` after the join and rejects the request whenever that relative path climbs out of the base directory (starts with `..`) or is itself absolute (which `path.relative` returns when the two paths sit on different drives on Windows, meaning `targetPath` isn't under `REPORTS_DIR` at all). This closes the traversal for both relative escapes and absolute/drive-letter overrides while still allowing any legitimate file name that stays inside `reports/`, including ones in nested subfolders. The 400 response for a rejected name mirrors the existing validation style (the empty-`fileName` check) so the handler's error-handling shape is unchanged, and the success path (`fs.readFile`, content type, response body) is untouched.
