## Verdict

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- Location: `PathJoinReadFile.js`, line 19 (`fs.readFile(targetPath, ...)`)
- Verdict: **exploitable**
- Confidence: high

## Source

`req.query.file` (the `file` query-string parameter on `GET /reports/download`) is attacker-controlled and reaches the sink with no validation, canonicalization, or containment check:

```
fileName = req.query.file
targetPath = path.join(REPORTS_DIR, fileName)   // line 16
fs.readFile(targetPath, 'utf8', ...)             // line 19 - sink
```

`path.join` collapses `..` segments arithmetically but does not stop the result from resolving outside `REPORTS_DIR` - a request such as `GET /reports/download?file=../../../../etc/passwd` (or a Windows equivalent traversal to read arbitrary files under the server's privileges) produces a `targetPath` outside the intended directory, which `fs.readFile` then opens and streams back verbatim in the response body.

## Fix

No third-party library is required; the fix uses Node's built-in `path`/`fs` APIs per the loaded JavaScript guidance (canonicalize both sides, then verify containment with `path.relative`).

**Vulnerable code:**

```js
const REPORTS_DIR = path.join(__dirname, 'reports');

router.get('/reports/download', (req, res) => {
  const fileName = req.query.file;

  if (!fileName) {
    return res.status(400).send('file query parameter is required');
  }

  const targetPath = path.join(REPORTS_DIR, fileName);

  // SAST FINDING: CWE-22 - no containment check before the file read
  fs.readFile(targetPath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).send('Report not found');
    }
    res.type('text/plain').send(data);
  });
});
```

**Fixed code:**

```js
const REPORTS_DIR = path.join(__dirname, 'reports');
const REPORTS_DIR_REAL = fs.realpathSync.native(REPORTS_DIR);

router.get('/reports/download', (req, res) => {
  const fileName = req.query.file;

  if (!fileName) {
    return res.status(400).send('file query parameter is required');
  }

  const targetPath = path.join(REPORTS_DIR, fileName);

  let realTargetPath;
  try {
    realTargetPath = fs.realpathSync.native(targetPath);
  } catch (err) {
    return res.status(404).send('Report not found');
  }

  const relative = path.relative(REPORTS_DIR_REAL, realTargetPath);
  const isContained =
    relative !== '..' &&
    !relative.startsWith('..' + path.sep) &&
    !path.isAbsolute(relative);

  if (!isContained) {
    return res.status(404).send('Report not found');
  }

  fs.readFile(realTargetPath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).send('Report not found');
    }
    res.type('text/plain').send(data);
  });
});
```

## Explanation

The fix resolves both the trusted base (`REPORTS_DIR_REAL`, computed once at module load) and the requested candidate path (`realTargetPath`, resolved per request) with `fs.realpathSync.native()`, which follows symlinks and normalizes `.`/`..` to their true on-disk location - so a value that only *looks* contained after `path.join` (e.g. via a symlink placed inside `reports/`, or an unresolved `../`) cannot slip through. Containment is then verified with `path.relative(REPORTS_DIR_REAL, realTargetPath)`, rejecting when the result is exactly `..`, starts with `'..' + path.sep`, or is itself absolute - a path-component-aware check rather than a raw string-prefix comparison, which a name like `reports-secret` would defeat. The read then uses `realTargetPath`, the resolved and validated value, rather than re-deriving or reusing the original tainted `targetPath`. Because `realpathSync` requires the target to already exist, a request for a nonexistent or out-of-bounds file both correctly resolve to the same generic `404 Report not found`, so the response gives an attacker no signal distinguishing "no such file" from "blocked traversal attempt".

## Behaviour changes

- **New module-load precondition:** `REPORTS_DIR_REAL` is resolved once at require-time via `fs.realpathSync.native(REPORTS_DIR)`. If `reports/` does not exist when the module loads, this now throws at startup instead of only failing lazily on first request. This is a deliberate trade-off to resolve the trusted base once rather than per request; if the reports directory can legitimately be created after process start, this line should move inside the handler (at a small per-request cost).
- **Symlinks inside `reports/` are no longer followed to targets outside it.** Any legitimate report file is a real file directly under `reports/`, so this narrows behavior only for symlinked entries pointing outside the directory - the traversal vector - not for ordinary reports.
- **Existence check moved earlier:** a missing or unresolvable file is now caught by the `realpathSync.native` try/catch and returns 404 there, rather than by the subsequent `fs.readFile` callback's `err` branch. The response (status, body text) is identical in both cases, so this is not observable to a client.
- No change to the success path's response: on a valid, contained file, the response is still `res.type('text/plain').send(data)` with the same file contents as before.
