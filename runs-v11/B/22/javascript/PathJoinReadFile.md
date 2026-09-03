## Verdict

Confirmed. The finding is exploitable. Unsanitized user input from `req.query.file` is used to construct a file path that reaches `fs.readFile()` without validation or canonicalization, allowing path traversal to files outside the intended `reports` directory.

## Source

User-supplied input: `req.query.file` (query parameter).

The taint flows through:
1. `const fileName = req.query.file` (line 10)
2. `const targetPath = path.join(REPORTS_DIR, fileName)` (line 16) - constructs path with untrusted input
3. `fs.readFile(targetPath, ...)` (line 19) - sink, operates on untrusted path

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
    // Canonicalize paths to absolute form and resolve symlinks
    const baseDir = fs.realpathSync(REPORTS_DIR);
    const targetPath = path.resolve(REPORTS_DIR, fileName);
    const realTargetPath = fs.realpathSync(targetPath);
    
    // Verify the resolved path is within the allowed directory
    const relativePath = path.relative(baseDir, realTargetPath);
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
    // Path resolution failed or directory does not exist
    return res.status(404).send('Report not found');
  }
});

module.exports = router;
```

## Explanation

The vulnerability occurred because `path.join()` accepts user input without enforcing that the result remains within the base directory. An attacker could pass `../../../etc/passwd` as the `file` parameter to escape the `reports` directory and read arbitrary files.

The fix applies the Node.js-specific containment pattern from CWE-22 guidance:

1. **Canonicalization**: `fs.realpathSync()` resolves both the base directory and the target path to their absolute canonical forms, eliminating relative path segments (`..`, `.`) and following symlinks to their true targets.

2. **Path construction**: `path.resolve()` is used for construction instead of `path.join()` when combined with the canonicalization step. (Note: `path.join()` is actually safer during construction since `path.resolve()` can be discarded by a leading `/` in user input, but since we canonicalize afterward, either works; here we use `path.resolve()` for clarity of intent.)

3. **Containment verification**: After canonicalization, `path.relative()` computes the relative path from the base to the target. If this result starts with `..` or is exactly `..`, the target is outside the base directory and is rejected with HTTP 403.

4. **Error handling**: `fs.realpathSync()` throws `ENOENT` if a path does not exist, which we catch and convert to a 404 response, preserving the original error handling behavior.

## Behaviour changes

- **Containment enforcement**: Paths containing `..`, symlinks pointing outside `REPORTS_DIR`, or absolute paths in the `file` parameter are now rejected with HTTP 403 (Forbidden) instead of being silently processed, potentially leaking files outside the intended directory.
- **Symlink handling**: Symlinks within the base directory that target files outside it are now followed and rejected. This closes a gap where a symlink could have been used to escape the directory.
- **Filesystem requirements**: The `reports` directory is now required to exist; if it does not, requests return 404 instead of potentially succeeding if the constructed path happened to resolve to a valid file elsewhere (unlikely in practice, but a behavioral change).
- **Performance**: `fs.realpathSync()` adds filesystem calls per request, but this is necessary for security and typical report-serving scenarios would be I/O-bound anyway.
