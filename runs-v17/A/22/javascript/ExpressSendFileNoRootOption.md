## Verdict
The code is vulnerable to path traversal (CWE-22). User input from `req.query.file` is joined with a base directory and passed to `res.sendFile()` without path boundary validation. An attacker can use sequences like `../` or absolute paths to access files outside the intended reports directory.

## Source
The vulnerability exists in the GET /reports/download route handler. The `requestedFile` parameter comes directly from `req.query.file` and is joined with `reportsDir` using `path.join()`, which does not prevent traversal. The resulting path is passed to `res.sendFile()` without restricting the file scope.

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

  // Use the root option to restrict file access to the reportsDir only.
  // Express will reject any path traversal attempts.
  res.sendFile(requestedFile, { root: reportsDir });
});

module.exports = router;
```

## Explanation
The fix uses Express's `root` option in `res.sendFile()` to establish a boundary. When the `root` option is specified, Express resolves the filename relative to that root directory and rejects any attempt to traverse outside it. This prevents attacks using `../`, absolute paths, or other traversal sequences. The filename is no longer pre-joined with the base directory; instead, Express handles the joining and enforces the boundary check internally.
