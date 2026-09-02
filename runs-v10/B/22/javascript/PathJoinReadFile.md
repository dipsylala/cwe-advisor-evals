## Verdict

Path traversal vulnerability confirmed. User-supplied `fileName` from `req.query.file` is joined with `REPORTS_DIR` and passed directly to `fs.readFile()` without canonicalization or containment verification. Attackers can read arbitrary files via sequences like `../../../../etc/passwd`.

## Source

```javascript
const fileName = req.query.file;
```

Line 10: untrusted query parameter, no decoding step.

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

  try {
    // Canonicalize both the base and candidate paths to resolve symlinks and relative references
    const baseReal = fs.realpathSync.native(REPORTS_DIR);
    const targetPath = path.join(REPORTS_DIR, fileName);
    const targetReal = fs.realpathSync.native(targetPath);
    
    // Verify the resolved path stays within the base directory
    const relativePath = path.relative(baseReal, targetReal);
    if (relativePath === '..' || relativePath.startsWith('..' + path.sep) || path.isAbsolute(relativePath)) {
      return res.status(403).send('Access denied');
    }

    fs.readFile(targetReal, 'utf8', (err, data) => {
      if (err) {
        return res.status(404).send('Report not found');
      }
      res.type('text/plain').send(data);
    });
  } catch (err) {
    return res.status(400).send('Invalid file path');
  }
});

module.exports = router;
```

## Explanation

The fix canonicalizes paths before use. `fs.realpathSync.native()` resolves both the base directory and the candidate path to their absolute, symlink-free forms. Then `path.relative()` computes the relative path from base to candidate; if the result is `..` (parent directory), starts with `.. + path separator`, or is absolute, the candidate escapes the base and is rejected. This prevents path traversal while preserving the ability to read legitimate files within `REPORTS_DIR`. The try-catch handles filesystem errors (e.g., nonexistent files) and invalid paths. The actual file read uses `targetReal`, the canonicalized path, ensuring the validation and the operation check the same file.

## Behaviour changes

- Invalid traversal attempts now return HTTP 403 instead of attempting file access
- Nonexistent or unreadable files return HTTP 404 with message "Report not found" (unchanged error response, but now guaranteed to be within `REPORTS_DIR`)
- Malformed paths that cannot be resolved throw and return HTTP 400; previously would error at `fs.readFile()`
- Symlinks within `REPORTS_DIR` are followed (standard behavior preserved); symlinks outside the base are rejected
