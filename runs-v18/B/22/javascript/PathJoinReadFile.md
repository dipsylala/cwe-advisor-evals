## Verdict

exploitable

## Source

`req.query.file` at line 10: user-supplied query parameter, untrusted input

## Sink

`fs.readFile(targetPath, ...)` at line 19: file read operation using a path constructed from untrusted input without containment validation

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

  try {
    // Construct the target path
    const targetPath = path.join(REPORTS_DIR, fileName);

    // Resolve both paths to their canonical forms
    const realBasePath = fs.realpathSync.native(REPORTS_DIR);
    const realTargetPath = fs.realpathSync.native(targetPath);

    // Check that the resolved path is within the base directory
    const relativePath = path.relative(realBasePath, realTargetPath);
    if (relativePath === '..' || relativePath.startsWith('..' + path.sep) || path.isAbsolute(relativePath)) {
      return res.status(403).send('Access denied');
    }

    fs.readFile(realTargetPath, 'utf8', (err, data) => {
      if (err) {
        return res.status(404).send('Report not found');
      }
      res.type('text/plain').send(data);
    });
  } catch (err) {
    return res.status(404).send('Report not found');
  }
});

module.exports = router;
```

## Explanation

The vulnerability occurs because the original code constructs a file path using `path.join(REPORTS_DIR, fileName)` without validating that the result remains within the intended directory. An attacker can supply `fileName = "../../etc/passwd"` and the constructed path will traverse outside REPORTS_DIR to access arbitrary files.

The fix resolves this by:
1. Using `fs.realpathSync.native()` to canonicalize both the base directory and the requested file path, resolving any symlinks and relative path components (`.`, `..`) to their absolute forms.
2. Computing the relative path from the canonical base to the canonical target using `path.relative()`.
3. Rejecting the request if the relative path equals `..`, starts with `.. + path.sep` (indicating traversal), or is absolute (indicating an attempted escape to the root).
4. Only if the containment check passes, reading from the validated canonical path.

This enforces that the file being read must be within the reports directory and cannot escape via path traversal sequences or symlinks.

## Behaviour changes

- Added try-catch wrapper around path resolution and validation. The catch block treats any exceptions (including ENOENT if the file doesn't exist, which realpathSync throws) as a 404 response, preserving the original error handling behavior.
- Changed the 404 error response to also handle the case where path resolution fails, maintaining the same HTTP status code.
- Added a 403 Forbidden response when path containment validation fails, allowing clients to distinguish between "file not found" (404) and "access denied" (403).
- Changed to read from `realTargetPath` (the canonical resolved path) instead of the unvalidated `targetPath`, ensuring the actual operation uses the validated path.

## Verification

Syntax check with Node.js `node --check`: passed (no errors)

All used APIs are standard Node.js built-ins available since Node 9.2+ (`fs.realpathSync.native()`, `path.join()`, `path.relative()`, `path.sep`, `path.isAbsolute()`). The fix does not introduce new external dependencies.

## Assumptions

None.
