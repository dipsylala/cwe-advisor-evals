## Verdict

exploitable (confidence: high)

- cwe_id: CWE-22
- location: PathJoinReadFile.js, line 19 (sink: `fs.readFile(targetPath, ...)`); constructing statement at line 16 (`path.join(REPORTS_DIR, fileName)`)

## Source

`req.query.file` (line 10, `fileName`) - an unvalidated, attacker-controlled Express query parameter, passed directly into `path.join()` at line 16 and used unchecked as the `fs.readFile()` argument at line 19.

`path.join()` does not strip `..` segments the way `path.resolve()` can be made to discard a base - it concatenates and normalizes, so `fileName = '../../../../etc/passwd'` (or a Windows-relevant `..\\..\\...`) resolves `targetPath` outside `REPORTS_DIR`, and the handler streams that file's contents back to the caller. There is no validation, allowlist, or containment check anywhere between the source and the sink, so the trace confirms an exploitable path, not merely an unconfirmed one.

## Fix

Library recommendation: none - this is fixable with Node's built-in `path`/`fs` APIs per the loaded CWE-22 JavaScript guidance; no third-party dependency is required.

Vulnerable code:
```js
const REPORTS_DIR = path.join(__dirname, 'reports');

router.get('/reports/download', (req, res) => {
  const fileName = req.query.file;

  if (!fileName) {
    return res.status(400).send('file query parameter is required');
  }

  const targetPath = path.join(REPORTS_DIR, fileName);

  // SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
  fs.readFile(targetPath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).send('Report not found');
    }
    res.type('text/plain').send(data);
  });
});
```

Fixed code:
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
  const escapesRoot =
    relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative);

  if (escapesRoot) {
    return res.status(400).send('Invalid file parameter');
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

The fix canonicalizes both the trusted base directory and the requested path with `fs.realpathSync.native()` (which resolves symlinks and `.`/`..` segments to their real, absolute form) and then verifies containment with `path.relative()`, per the CWE-22 JavaScript guidance: the result is rejected if it is exactly `..`, starts with `'..' + path.sep`, or is itself absolute - a path-component-aware check rather than a raw string-prefix comparison. Because `realpathSync` requires the target to exist, resolution failure (including a traversal attempt aimed at a nonexistent path, or a legitimate missing report) is caught and mapped to the same 404 the original code already returned for a missing file, so that response is unchanged for the common not-found case. Only a request whose canonical path successfully resolves but lands outside `REPORTS_DIR_REAL` is treated as a traversal attempt and rejected with 400. The canonicalized `realTargetPath` - not the original tainted `fileName` or the unresolved `targetPath` - is the value passed to `fs.readFile()`, closing the gap between what was validated and what was ultimately read.

## Behaviour changes

- Added a synchronous `fs.realpathSync.native()` resolution (module-load time for `REPORTS_DIR`, per-request for the candidate path) before the existing async `fs.readFile()` call. This introduces a small amount of blocking I/O into the request handler; it is the mechanism the language guidance specifies for symlink-safe canonicalization and has no built-in async equivalent that resolves symlinks the same way.
- A request whose resolved path exists on disk but falls outside `REPORTS_DIR` now receives `400 Invalid file parameter` instead of the file's contents (previously a successful 200 leak). This is the intended effect of the fix, not a side effect.
- A request whose path fails to resolve (nonexistent file, or a traversal attempt aimed at a nonexistent path) is mapped to the pre-existing `404 Report not found` response, so the previously observable "missing file" behaviour is preserved for that case; the underlying error is now `realpathSync`'s `ENOENT` rather than `fs.readFile`'s, but the caller-visible status and body are identical.
- All other behaviour - the missing-query-parameter 400, the `text/plain` success response, and the 404 for a resolvable-but-unreadable file - is unchanged.
