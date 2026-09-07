## Verdict

Exploitable. The user-supplied `fileName` parameter flows directly into `path.join(REPORTS_DIR, fileName)` without validation or containment enforcement. An attacker can supply traversal sequences like `../../../etc/passwd` to escape the reports directory and read arbitrary files on the system. The sink `fs.readFile(targetPath)` operates on the unchecked path.

## Source

`req.query.file` on line 10 – HTTP query parameter, attacker-controlled. No validation occurs before this value is used.

## Fix

**Vulnerable code:**
```javascript
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
```

**Fixed code:**
```javascript
const fileName = req.query.file;

if (!fileName) {
  return res.status(400).send('file query parameter is required');
}

try {
  // Resolve the base directory to its real absolute path
  const realReportsDir = fs.realpathSync.native(REPORTS_DIR);
  
  // Construct the candidate path
  const targetPath = path.join(REPORTS_DIR, fileName);
  
  // Resolve the target to its real absolute path
  const realTargetPath = fs.realpathSync.native(targetPath);

  // Verify the real target path stays within the real base directory
  const relativePath = path.relative(realReportsDir, realTargetPath);
  if (relativePath === '..' || relativePath.startsWith('..' + path.sep) || path.isAbsolute(relativePath)) {
    return res.status(403).send('Access denied');
  }

  // Path is safely contained; read the file
  fs.readFile(realTargetPath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).send('Report not found');
    }
    res.type('text/plain').send(data);
  });
} catch (err) {
  // Handle file not found or other filesystem errors during path resolution
  return res.status(404).send('Report not found');
}
```

## Explanation

The fix uses `fs.realpathSync.native()` on both the base directory (`REPORTS_DIR`) and the constructed target path to resolve them to their real absolute canonical forms. This resolves all symlinks, relative references (`.` and `..`), and case normalization. After resolution, `path.relative(realReportsDir, realTargetPath)` computes the relative path from the base to the target. If this relative path equals `..`, starts with `'..' + path.sep`, or is absolute, the target escapes the base directory and is rejected with a 403 response. Only paths that remain safely inside the base directory proceed to `fs.readFile()` with the validated resolved path. This eliminates the path traversal attack vector: even if the attacker supplies `../../../etc/passwd`, the real path resolution and containment check will reject it.

## Behaviour changes

1. **Exception handling added**: The fix wraps path resolution in a try-catch block. Errors during `realpathSync.native()` – such as ENOENT if the file doesn't exist – are caught and return a 404 response. This preserves the original behavior of returning 404 for missing files, but now also handles path resolution errors.

2. **Containment check added**: A new validation step checks that the real target path stays within the real base directory. Requests attempting path traversal now receive a 403 "Access denied" response instead of silently reading arbitrary files. This is an intentional behavior change that prevents the vulnerability.

3. **Uses resolved path for file read**: The `fs.readFile()` call now uses `realTargetPath` (the canonically resolved path) instead of the unvalidated `targetPath`. This ensures the actual file operation works on the validated path.

4. **No change to success response**: When a file is successfully read, the response (200 with `text/plain` content type and file data) remains identical to the original behavior.
