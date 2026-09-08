## Verdict

Confirmed. `requestedFile` comes from `req.query.file`, an attacker-controlled query
string parameter, and is joined onto `reportsDir` with `path.join()` before being
passed to `res.sendFile()`. `path.join()` normalizes `..` segments but does not
strip them, so a value such as `../../../../etc/passwd` (or, on the target
platform, a path pointing at another sensitive file) collapses back out of
`reportsDir` before `sendFile` ever sees the result. Because `sendFile()` is
called without a `root` option, Express treats the joined value as an absolute
path and serves whatever it resolves to, with no containment check.

## Source

`req.query.file` in `router.get('/reports/download', ...)`, line 13
(`E:/Github/cwe-advisor/evals/cases/22/javascript/ExpressSendFileNoRootOption/ExpressSendFileNoRootOption.js`).

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

  if (!requestedFile || typeof requestedFile !== 'string') {
    return res.status(400).send('Missing file parameter');
  }

  // Pass the raw, unjoined filename together with the `root` option so
  // Express (via the `send` module) resolves it against reportsDir and
  // rejects any path - including ones using `..` or an absolute path -
  // that would resolve outside that directory, instead of pre-joining
  // the path ourselves and only then handing it to sendFile.
  res.sendFile(requestedFile, { root: reportsDir }, (err) => {
    if (err) {
      if (!res.headersSent) {
        const status = err.status || 500;
        res.status(status).send(status === 404 ? 'File not found' : 'Unable to send file');
      }
    }
  });
});

module.exports = router;
```

## Explanation

The vulnerable code builds the path itself with `path.join(reportsDir,
requestedFile)` and only then calls `res.sendFile(reportPath)` with no `root`
option. `path.join` collapses `..` segments arithmetically but does nothing to
stop the final path from landing outside `reportsDir`, and without a `root`
option `sendFile` treats whatever string it is given as an absolute path to
serve directly - there is no boundary check at either step.

The fix removes the manual `path.join` entirely and instead passes the raw,
attacker-controlled `requestedFile` string straight to `res.sendFile()` along
with `{ root: reportsDir }`. With a `root` option present, Express's
underlying `send` module resolves the supplied path against that root and
explicitly rejects any result that escapes it (including via `..` traversal
or an absolute-path override), returning a 403 instead of serving the file.
This is the mechanism Express's own documentation prescribes for exactly this
case - "recommended... to always use root as an option, in addition to
validating the input path." A `typeof` check is also added because
`req.query.file` can arrive as an array or object (e.g. `?file[]=x`) when a
client sends the parameter more than once, and only a string is a valid
`sendFile` argument.

An error callback is added because passing a `root` option changes `sendFile`
error semantics: a rejected or missing path now surfaces as an error to the
callback rather than Express's default unhandled-error behavior, so the route
needs to convert that into a proper HTTP response.
