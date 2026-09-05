## Verdict

Confirmed. Path traversal vulnerability via unsanitized file path parameter.

## Source

Line 10: `const fileName = req.query.file;` — untrusted user input from query parameter  
Line 16: `const targetPath = path.join(REPORTS_DIR, fileName);` — fileName used to construct file path without validation  
Line 19: `fs.readFile(targetPath, 'utf8', ...)` — sink: file read with unvalidated path

Data flow: User-supplied `fileName` is passed directly to `path.join()` which combines it with the base directory. An attacker can provide `fileName = "../../etc/passwd"` or similar traversal sequences to read files outside the intended directory.

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

  const targetPath = path.join(REPORTS_DIR, fileName);

  try {
    // Canonicalize both paths to resolve symlinks and relative references
    const realReportsDir = fs.realpathSync.native(REPORTS_DIR);
    const realTargetPath = fs.realpathSync.native(targetPath);
    
    // Verify the resolved path stays within the allowed directory
    const relativePath = path.relative(realReportsDir, realTargetPath);
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

The fix eliminates the path traversal by canonicalizing and validating the file path before reading. 

**Canonicalization** (`fs.realpathSync.native()`): Resolves the constructed path to its true absolute form, following symlinks and collapsing relative references (`.`, `..`). This prevents symlink-based escapes and normalizes encoding variations.

**Containment validation** (`path.relative()`): Computes the relative path from the base directory to the resolved target. If the result starts with `..` or is an absolute path, it indicates the target is outside the permitted directory and is rejected with a 403 status.

**Single resolution**: The resolved path is computed once and reused in the `fs.readFile()` call, preventing time-of-check-time-of-use (TOCTOU) race conditions where an attacker could manipulate filesystem state between validation and file access.

The fix uses Node.js built-in modules (no new dependencies required) and preserves the original behavior for legitimate requests — valid file names within the directory are still read and returned as text/plain.

## Behaviour changes

- **Attack case (traversal attempt)**: A request with `file=../../etc/passwd` is rejected with HTTP 403 "Access denied" instead of potentially exposing the file contents.
- **Symlink escape**: A symlink within the reports directory pointing outside is now rejected instead of followed.
- **Legitimate requests**: Valid file names (e.g., `file=report.txt`) continue to work as before, reading from the reports directory and returning the file content.
- **Error handling**: File-not-found errors (missing files in the reports directory) still return HTTP 404. Errors from path resolution (permissions, invalid paths) also return 404.
- **Performance**: Minimal impact — one additional `fs.realpathSync.native()` call per request (filesystem operation is very fast).
