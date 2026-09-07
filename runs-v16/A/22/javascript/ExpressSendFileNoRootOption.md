## Verdict
VULNERABLE: Path traversal is possible because `res.sendFile()` is called without the `root` option, allowing an attacker to escape the intended directory using path traversal sequences like `../`.

## Source
Line 22: `res.sendFile(reportPath);`

The path is constructed from untrusted user input (`req.query.file`) on line 19 and passed directly to `sendFile()` without directory confinement.

## Fix
```javascript
const express = require('express');
const path = require('path');

const router = express.Router();

// Directory where generated customer reports are stored on disk.
const reportsDir = path.join(__dirname, 'generated-reports');

// GET /reports/download?file=quarterly-summary.pdf
// Lets a signed-in customer download one of their previously generated
// report files by name.
router.get('/reports/download', (req, res) => {
  const requestedFile = req.query.file;

  if (!requestedFile) {
    return res.status(400).send('Missing file parameter');
  }

  // FIXED: Use the root option to confine file serving to the intended directory
  res.sendFile(requestedFile, { root: reportsDir });
});

module.exports = router;
```

## Explanation
The fix uses Express's `root` option in `sendFile()` to enforce that files can only be served from within `reportsDir`. When `root` is specified, Express resolves the file parameter as relative to the root directory and prevents path traversal attacks.

With the original code, `path.join(reportsDir, requestedFile)` would allow an attacker to pass `file=../../../etc/passwd` which would resolve outside the intended directory. With the fixed code, the same traversal attempt fails because `sendFile()` with the `root` option validates that the resolved path remains within the specified root directory.

The change is minimal: pass `requestedFile` (just the filename) as the first argument and specify `{ root: reportsDir }` as options, rather than pre-joining the paths.
