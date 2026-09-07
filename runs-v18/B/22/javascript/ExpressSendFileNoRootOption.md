## Verdict
Exploitable

## Source
Line 13: `const requestedFile = req.query.file;` - untrusted user input from query parameter

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

  // FIXED: Use the root option to enforce containment. Express validates
  // that the resolved path stays within the specified root directory.
  res.sendFile(requestedFile, { root: reportsDir });
});

module.exports = router;
```

## Explanation
The original code constructs a full path by joining the user-supplied filename with the reports directory, then passes it to `res.sendFile()` without validation. This allows path traversal attacks using `../` sequences to access files outside the intended directory. The fix uses Express's built-in `root` option with `res.sendFile()`, which enforces containment at the framework level: the relative filename is passed as the first argument, the base directory is specified in the `root` option, and Express internally validates that the resolved path remains within that root. This is the framework's own containment mechanism and is more reliable than manual validation.

## Behaviour changes
The resolved path is now validated by Express against the root directory. The original code passed an absolute or unvalidated path to `res.sendFile()` with no containment check; the fixed code passes a relative path with the `root` option set, which enforces directory confinement. No other behaviour changes: the file is still served to the client, error handling for missing files is preserved, and the response content type is determined the same way by Express.
