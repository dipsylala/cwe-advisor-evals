## Verdict

exploitable (confidence: high)

## Source

`req.query.file` (the `file` query-string parameter on `GET /reports/download`) - fully attacker-controlled, no allowlist or type constraint.

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

  const targetPath = path.join(REPORTS_DIR, fileName);

  let realBase;
  let realTarget;
  try {
    realBase = fs.realpathSync.native(REPORTS_DIR);
    realTarget = fs.realpathSync.native(targetPath);
  } catch (err) {
    return res.status(404).send('Report not found');
  }

  const relative = path.relative(realBase, realTarget);
  const isContained = relative === '' ||
    (!relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative));

  if (!isContained) {
    return res.status(404).send('Report not found');
  }

  fs.readFile(realTarget, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).send('Report not found');
    }
    res.type('text/plain').send(data);
  });
});

module.exports = router;
```

## Explanation

`fileName` reaches `path.join(REPORTS_DIR, fileName)` and then `fs.readFile()` with no validation, so a value such as `../../../../etc/passwd` (or any absolute path segment `path.join` does not discard) escapes `REPORTS_DIR` - `path.join` normalizes `..` segments arithmetically but does not confine the result to the base directory. The fix resolves both the base directory and the candidate target to their real, symlink-free absolute paths with `fs.realpathSync.native()` (Node 9.2+), then uses `path.relative()` between the two real paths as the containment check: an empty result means the target is the base itself, and any result that is exactly `..`, starts with `'..' + path.sep`, or is itself absolute means the target fell outside the base and is rejected. `realpathSync` requires the target to exist, which matches this read-only sink (a nonexistent path already produced the same "Report not found" outcome the caller expects). The subsequent `fs.readFile()` is switched to read the already-resolved `realTarget` rather than re-deriving the path, so the value that was checked is the value that is used.

## Behaviour changes

- A request whose resolved target lies outside `REPORTS_DIR` (or that names something not on disk) now returns `404 Report not found` synchronously from the containment check instead of failing inside the `fs.readFile` callback - the response is identical, only the origin of the same status/body moved earlier.
- If `fileName` resolves through a symlink to a file physically outside `REPORTS_DIR`, it is now rejected; previously such a symlink would have been followed and served. This is the intended closure of the weakness, not incidental.
- No change to the success path: a legitimate `fileName` still returns the file's contents as `text/plain` via the same `fs.readFile(..., 'utf8', ...)` call and callback shape.

## Assumptions

None - `fs.realpathSync.native()` and the `path.relative()` containment pattern are named directly in `cwe/22/javascript/INDEX.md`, and the sink's existing 404-on-error contract is preserved rather than altered.

## Verification

`node --check` against a scratch copy of the fixed file (outside the repo) returned no syntax errors. No test runner or dependency graph was available in this context, so the file was reviewed by hand against the original for API correctness: `fs.realpathSync.native`, `path.relative`, `path.sep`, and `path.isAbsolute` are all standard Node core-module APIs referenced by name in the loaded language guidance; no new package or import was introduced.
