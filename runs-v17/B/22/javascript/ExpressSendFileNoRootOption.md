## Verdict

Exploitable

## Source

`req.query.file` (line 13) - user-supplied query parameter, untrusted and unvalidated.

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

  // Extract just the filename to prevent path traversal
  const filename = path.basename(requestedFile);

  // Use the root option to enforce that the file stays within reportsDir
  res.sendFile(filename, { root: reportsDir });
});

module.exports = router;
```

## Explanation

The vulnerability exists because `req.query.file` is joined directly with `reportsDir` using `path.join()` without any containment validation, and then passed to `res.sendFile()` without the `root` option. An attacker can supply `../../../etc/passwd` or similar traversal sequences to access files outside the intended reports directory. The fix applies two layers: (1) extract only the filename component using `path.basename()` to strip any directory components the attacker may have injected, and (2) pass the filename along with the `root` option to `res.sendFile()`, which Express uses to validate that the resolved path stays within the specified root directory. This combines the framework's built-in containment mechanism with filename-only input, eliminating the traversal path.

## Behaviour changes

**Argument addition**: `res.sendFile()` now receives a second argument, `{ root: reportsDir }`, which Express uses to constrain path resolution. This is the framework's native containment check and does not alter the response or return value.

**Path transformation**: The input `requestedFile` is now passed through `path.basename()` before being sent to `res.sendFile()`. `path.basename()` extracts only the final filename component, stripping any directory separators or traversal sequences. For example, `../../../etc/passwd` becomes `passwd`, and `foo/bar/baz.txt` becomes `baz.txt`. This ensures only a simple filename (no path components) reaches the sink, which combined with the `root` option provides complete containment.

These changes preserve the existing behavior for legitimate filenames: a user requesting `quarterly-summary.pdf` still receives that file from `reportsDir`, exactly as before. Only traversal attempts are blocked.

