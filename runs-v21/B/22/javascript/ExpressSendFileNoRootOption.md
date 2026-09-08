## Verdict

Exploitable. User-supplied input from `req.query.file` flows through `path.join()` into `res.sendFile()` without containment validation, allowing path traversal attacks to access files outside the intended directory.

## Source

Input source: `req.query.file` (line 13)

Data flow:
1. User-supplied `file` parameter from query string
2. Passed to `path.join(reportsDir, requestedFile)` (line 19)
3. Result used in `res.sendFile(reportPath)` (line 22) without validation

An attacker can supply sequences like `file=../../../../etc/passwd` to traverse outside `reportsDir`.

## Fix

### File: ExpressSendFileNoRootOption.js

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

  res.sendFile(requestedFile, { root: reportsDir });
});

module.exports = router;
```

## Explanation

The fix applies Express's built-in path containment mechanism by adding the `root` option to `res.sendFile()`. When `root` is specified, Express validates that the resolved path stays within that directory before serving the file. This eliminates the traversal by delegating the containment check to the framework's own handler, which is the recommended pattern in the CWE-22 guidance for JavaScript. The removed line that constructed `reportPath` is no longer needed because Express performs path resolution and validation internally when `root` is supplied.

## Behaviour changes

- Removed line 19: `const reportPath = path.join(reportsDir, requestedFile);` — no longer needed since Express handles path resolution with the `root` option.
- Changed line 22 from `res.sendFile(reportPath)` to `res.sendFile(requestedFile, { root: reportsDir })` — adds Express's framework-level containment validation.
- Express will now return a 403 Forbidden or similar error if the resolved path attempts to escape `reportsDir`, instead of serving the out-of-bounds file.

This is a pure containment fix with no impact on the success path for legitimate requests — files within the reports directory are served normally with no behavioral change.
