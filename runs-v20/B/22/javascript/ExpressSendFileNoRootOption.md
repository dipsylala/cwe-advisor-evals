## Verdict

CWE-22 (Improper Limitation of a Pathname to a Restricted Directory / Path Traversal) - **exploitable**. Confidence: high.

Location: `ExpressSendFileNoRootOption.js`, line 22 (`res.sendFile(reportPath)`).

`reportsDir` is an absolute path (`path.join(__dirname, 'generated-reports')`), so `reportPath = path.join(reportsDir, requestedFile)` is also absolute. `res.sendFile()` called without an `options.root` requires an absolute path and performs no containment check of its own on that path - Express only validates containment when `root` is supplied. `path.join()` collapses `..` segments arithmetically rather than rejecting them, so a request such as `?file=../../../../etc/passwd` (or a Windows equivalent traversal targeting a sensitive file) resolves outside `generated-reports` and is served as-is. Nothing between the query parameter and the sink constrains, canonicalizes, or contains the value.

## Source

- **Source**: `req.query.file` (line 13), the unauthenticated/unvalidated `file` query-string parameter.
- **Flow**: `requestedFile` is concatenated into a filesystem path with `path.join(reportsDir, requestedFile)` (line 20) and stored in `reportPath` with no traversal check.
- **Sink**: `res.sendFile(reportPath)` (line 22), called with no `root` option, so Express treats `reportPath` as an absolute path to serve directly.

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

  // Pass reportsDir as the `root` option so Express resolves requestedFile
  // against it and rejects anything that escapes that directory, instead of
  // trusting a path we built ourselves.
  res.sendFile(requestedFile, { root: reportsDir });
});

module.exports = router;
```

## Explanation

The fix removes the hand-built, unvalidated `reportPath` and instead calls `res.sendFile(requestedFile, { root: reportsDir })`. Express's documented behaviour for `sendFile()` with a `root` option is that the supplied path may be relative - and may even contain `..` - because Express resolves it against `root` and rejects anything that resolves outside that directory, before touching the filesystem. This is the framework's own containment mechanism for this exact sink, named directly in the knowledge base's JavaScript guidance for CWE-22, so it replaces the manual `path.join()` construction rather than adding a parallel hand-written check on top of it. The 400 response for a missing `file` parameter is unchanged, since that check is unrelated to the traversal weakness.

## Behaviour changes

- **Path construction removed**: the `reportPath` variable and its `path.join(reportsDir, requestedFile)` call are gone; `requestedFile` is now passed to `res.sendFile()` directly, with `reportsDir` moved into the `root` option. This is the fix itself - `path.join()` performed no containment check, and `root` is what supplies one.
- **Failure behaviour on a traversal attempt changes from "serves whatever the resolved absolute path points to" to "Express rejects the request when the resolved path falls outside `root`"**. This is the intended effect of the fix, not a side effect - the endpoint's contract for a *legitimate* filename in `generated-reports` (200 with the file streamed) is unchanged; only out-of-root requests, which should never have succeeded, now fail instead.
- **No other differences**: no new dependencies, no change to the 400 "Missing file parameter" branch, no change to success-path response headers or streaming behaviour that `res.sendFile()` otherwise provides.
- **Verification**: `node --check` was run against the fixed file (copied to a scratch location, not the shared fixture) and reported no syntax errors. `res.sendFile(path, options)` and the `root` option are Express's own documented API (already imported via `express.Router()` in the original file); no new package or import was introduced.
