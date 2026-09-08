## Verdict

Real issue. CWE-22 path traversal vulnerability in `fs.readFile()` sink. User-supplied `fileName` parameter is passed unsanitized through `path.join()` without containment verification, allowing traversal outside REPORTS_DIR via sequences like `../../etc/passwd`. Fix applies canonicalization and path-component-aware containment check per CWE-22 JavaScript guidance.

## Source

**Source:** `req.query.file` query parameter (untrusted user input)

**Sink:** `fs.readFile(targetPath, ...)` at line 19

**Data flow:** User input `fileName` is concatenated with `REPORTS_DIR` using `path.join(REPORTS_DIR, fileName)` at line 16, producing `targetPath`, which is then passed to `fs.readFile()` without validation that it remains within the base directory.

**Vulnerability:** `path.join()` resolves relative path segments (`.` and `..`), so an attacker input of `"../../etc/passwd"` results in `path.join(REPORTS_DIR, "../../etc/passwd")` resolving to `/etc/passwd`, escaping the intended directory boundary.

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

  // Reject null bytes in the filename
  if (typeof fileName !== 'string' || fileName.includes('\0')) {
    return res.status(400).send('Invalid file name');
  }

  try {
    // Resolve both the base directory and the requested path to their real, canonical forms
    const realBase = fs.realpathSync.native(REPORTS_DIR);
    const targetPath = path.join(REPORTS_DIR, fileName);
    const realTarget = fs.realpathSync.native(targetPath);

    // Verify the resolved path is contained within the base directory
    const relative = path.relative(realBase, realTarget);
    if (relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) {
      return res.status(403).send('Access denied');
    }

    // Path is safe; proceed with reading the file
    fs.readFile(realTarget, 'utf8', (err, data) => {
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

The fix applies three layers of defence per CWE-22 JavaScript guidance:

1. **Null byte rejection:** Untrusted input is checked for null bytes before path resolution to prevent potential bypass techniques.

2. **Canonicalization:** Both the base directory (`REPORTS_DIR`) and the constructed target path are resolved to their real, canonical forms using `fs.realpathSync.native()`. This resolves relative path segments (`..`, `.`), follows symlinks, and converts both paths to absolute form. All subsequent comparisons work on these canonical forms, ensuring consistent behaviour across different filesystem spellings.

3. **Path containment verification:** After canonicalization, `path.relative()` is called to compute the relative path from the real base to the real target. The result is checked: if it equals exactly `..`, starts with `.. + path.sep` (indicating traversal above the base), or is absolute (defensive check), access is rejected with a 403 Forbidden response. Only if the relative path represents a file inside the base directory does execution proceed to `fs.readFile()`.

The fix uses the safe path construction pattern: `path.join()` (which processes segments left-to-right) rather than `path.resolve()` (which discards the base if the user input starts with `/`), and passes the validated canonical path to the file operation, not the original untrusted value.

## Behaviour changes

- **New rejection:** Requests with file names containing null bytes are rejected with HTTP 400.
- **New rejection:** Requests attempting traversal outside REPORTS_DIR (e.g., `?file=../../etc/passwd`) are rejected with HTTP 403 Forbidden instead of succeeding.
- **Path resolution error:** Errors during path canonicalization (e.g., REPORTS_DIR does not exist, or a constructed path does not exist) are caught and return HTTP 404 "Report not found", matching the existing error-handling contract.
- **File access:** Successful requests read from the canonicalized path, ensuring that even if a file is accessed via a symlink or alternative spelling, it is always verified to be within the base directory.
