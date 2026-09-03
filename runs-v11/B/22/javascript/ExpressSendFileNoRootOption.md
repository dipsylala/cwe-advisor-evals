## Verdict

Exploitable. The code passes user-supplied input (`req.query.file`) through `path.join()` to construct a file path and sends it to `res.sendFile()` without validating that the resolved path remains within the intended `reportsDir` directory. An attacker can use path traversal sequences (e.g., `../`) to access files outside the restricted directory.

## Source

`req.query.file` (line 13) — user-supplied query parameter, decoded by Express before the code sees it.

## Fix

**Vulnerable code:**
```javascript
const requestedFile = req.query.file;

if (!requestedFile) {
  return res.status(400).send('Missing file parameter');
}

const reportPath = path.join(reportsDir, requestedFile);

res.sendFile(reportPath);
```

**Fixed code:**
```javascript
const requestedFile = req.query.file;

if (!requestedFile) {
  return res.status(400).send('Missing file parameter');
}

res.sendFile(requestedFile, { root: reportsDir });
```

## Explanation

Express's `res.sendFile()` with the `root` option performs containment validation automatically. When `root` is set, Express resolves the relative path argument within that directory and verifies the result stays within `root` boundaries. This is Express's own framework-level containment mechanism and is preferable to manual path resolution and validation. Removing the manual `path.join()` call and passing the filename directly with `{ root: reportsDir }` eliminates the path traversal window — Express will reject any path that attempts to escape the base directory, whether through `../` sequences or absolute paths.

## Behaviour changes

1. The `reportPath` intermediate variable is no longer needed and can be removed.
2. The `path.join()` call is eliminated; path resolution is delegated to Express's `res.sendFile()` method, which includes containment validation.
3. No changes to the signature or return value of `res.sendFile()` — the framework handles errors and response transmission identically.
4. The trade-off is intentional: the manual path-join approach provided no security benefit but made validation invisible; the `root` option makes validation explicit and is the framework's recommended pattern for this scenario.
