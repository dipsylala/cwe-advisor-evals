## Verdict

**CONFIRMED** - CWE-22 Path Traversal vulnerability. The application constructs a file path from untrusted user input (`req.query.file`) and passes it to `res.sendFile()` without enforcing containment within the intended directory.

## Source

The vulnerability exists in line 22 where `res.sendFile(reportPath)` is called without a `root` option. The `reportPath` is constructed by joining user-supplied input (`req.query.file`) with `reportsDir` using `path.join()`, but `path.join()` does not validate containment. An attacker providing `file=../../etc/passwd` would reach files outside the intended reports directory.

**Data flow:**
1. Source: `req.query.file` (untrusted user input from query parameter)
2. Construction: `path.join(reportsDir, requestedFile)` (concatenates without validation)
3. Sink: `res.sendFile(reportPath)` (transfers file without containment check)

Without the `root` option, Express does not validate that the path argument remains within a safe directory. This allows path traversal attacks.

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

  // Use the root option to enforce containment within reportsDir.
  // Express validates that the resolved path stays within root.
  res.sendFile(requestedFile, { root: reportsDir });
});

module.exports = router;
```

## Explanation

The fix uses Express's built-in `root` option in `res.sendFile()`. When the `root` option is specified, Express treats the path argument as relative to the root directory and validates that the resolved path stays within it. This eliminates the path traversal vulnerability.

**Key changes:**
- Removed the manual `path.join(reportsDir, requestedFile)` construction
- Pass `requestedFile` directly (the user-supplied filename)
- Add `{ root: reportsDir }` option to enforce containment

Express's path validation is more robust than hand-written checks. It canonicalizes paths and prevents escape attempts using sequences like `../`, `..\\`, and other traversal vectors. An attacker providing `file=../../etc/passwd` will now be rejected because the resolved path would escape `reportsDir`.

## Behaviour changes

**Before:** User can request any file on the system by providing path traversal sequences.

**After:** 
- Requests for files with path separators (`../`, `..\\`) or absolute paths are rejected
- The application can only serve files within the `generated-reports` directory
- Legitimate requests for files within that directory (e.g., `file=quarterly-summary.pdf`) continue to work as before
- The HTTP response for traversal attempts varies by Express version, but the file is not served in any case
