## Verdict

exploitable

## Source

`req.query.file` (line 10) - untrusted attacker-controlled input from HTTP query parameter

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

  // Reject null bytes before path processing
  if (fileName.includes('\0')) {
    return res.status(400).send('Invalid file name');
  }

  try {
    // Canonicalize both paths to resolve symlinks and relative references
    const resolvedBase = fs.realpathSync.native(REPORTS_DIR);
    const candidatePath = path.join(REPORTS_DIR, fileName);
    const resolvedCandidate = fs.realpathSync.native(candidatePath);

    // Verify the resolved candidate stays within the base directory
    const relative = path.relative(resolvedBase, resolvedCandidate);

    // Reject if path traversal is detected
    if (relative === '..' || relative.startsWith('..' + path.sep)) {
      return res.status(403).send('Access denied');
    }

    fs.readFile(resolvedCandidate, 'utf8', (err, data) => {
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

The original code was vulnerable to path traversal because it accepted user input directly in constructing file paths via `path.join(REPORTS_DIR, fileName)` without validation. An attacker could provide input like `../../../etc/passwd` to escape the reports directory. The fix closes this by canonicalizing both the base and candidate paths using `fs.realpathSync.native()`, which resolves symlinks and relative references (`.`, `..`) to their real absolute form. After canonicalization, `path.relative()` verifies that the candidate path remains within the base directory—rejecting any attempt to traverse outside yields exactly `..` or starts with `.. + path.sep`. The fixed code uses the validated `resolvedCandidate` for the actual file read operation. Additionally, null bytes are checked defensively before any path processing to prevent null-byte injection attacks.

## Behaviour changes

- Traversal attempts (e.g., `file=../../../etc/passwd`) now return 403 Forbidden instead of potentially reading files outside the intended directory
- Invalid null bytes in filenames now return 400 Bad Request instead of being passed to `fs.realpathSync()`
- Path resolution errors (e.g., missing base directory or permission issues on canonicalization) are caught and return 404 Not Found instead of propagating as unhandled exceptions
- File operations now use canonicalized real paths from `fs.realpathSync.native()` instead of relative path strings, ensuring symlink attacks cannot escape the base directory
- Distinguishes between access denied (403) and file not found (404) to provide better security signalling
- Verification applied: `node --check` syntax verification on fixed code — no errors

