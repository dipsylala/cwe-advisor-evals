## Verdict

Confirmed. `req.query.file` is attacker-controlled and is joined onto `REPORTS_DIR` with `path.join()` without any validation, then passed directly to `fs.readFile()`. `path.join()` normalizes `..` segments but does not restrict the result to stay under `REPORTS_DIR` - a value such as `../../etc/passwd` (or an absolute path, which `path.join` also allows to override the base on some inputs) escapes the intended directory and lets the caller read arbitrary files reachable by the process.

## Source

`req.query.file` on line 10 (the `fileName` variable), read from the `file` query-string parameter of the `GET /reports/download` request.

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

  // Strip any directory components the client tried to smuggle in, then
  // resolve and confirm the final path is still inside REPORTS_DIR.
  const safeName = path.basename(fileName);
  const targetPath = path.resolve(REPORTS_DIR, safeName);
  const resolvedDir = path.resolve(REPORTS_DIR) + path.sep;

  if (!targetPath.startsWith(resolvedDir)) {
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

`path.basename(fileName)` discards any directory separators or `..` segments the client supplied, collapsing the input to a bare file name so it cannot climb out of `REPORTS_DIR` by itself. The subsequent `path.resolve` + prefix check is a defense-in-depth boundary check: it resolves the final path and confirms it still falls under the resolved `REPORTS_DIR` (with a trailing separator appended before the comparison, so a sibling directory that merely shares `REPORTS_DIR` as a string prefix, e.g. `reports-archive`, is not mistaken for a match) before the file is touched, rejecting anything that would still land outside the reports directory. Combining a name-only allowlist with a resolved-path boundary check means the fix does not depend on `fs.readFile` ever seeing an unvalidated path, even if a future edit changes how `fileName` is constructed upstream.
