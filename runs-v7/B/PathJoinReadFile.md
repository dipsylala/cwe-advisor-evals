## Verdict

Real - path traversal is exploitable. User input is used directly in `path.join()` without validating that the result remains within `REPORTS_DIR`.

## Source

Line 10: `const fileName = req.query.file;` — untrusted user input from query parameter.

## Fix

**Vulnerable code (line 16-19):**
```javascript
const targetPath = path.join(REPORTS_DIR, fileName);

fs.readFile(targetPath, 'utf8', (err, data) => {
```

**Fixed code:**
```javascript
const router = express.Router();
const REPORTS_DIR = path.join(__dirname, 'reports');

// Resolve REPORTS_DIR to real path for containment checks
let realReportsDir;
try {
  realReportsDir = fs.realpathSync.native(REPORTS_DIR);
} catch (err) {
  realReportsDir = path.resolve(REPORTS_DIR);
}

// Streams a generated report back to the caller by file name.
router.get('/reports/download', (req, res) => {
  const fileName = req.query.file;

  if (!fileName) {
    return res.status(400).send('file query parameter is required');
  }

  const targetPath = path.join(REPORTS_DIR, fileName);

  // Resolve target path and validate containment
  let realTargetPath;
  try {
    realTargetPath = fs.realpathSync.native(targetPath);
  } catch (err) {
    return res.status(404).send('Report not found');
  }

  // Verify resolved path stays within base directory
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
});
```

## Explanation

The vulnerability allows an attacker to pass `../../etc/passwd` in the `file` query parameter, which `path.join()` does not validate. The fix:

1. Resolves the base directory `REPORTS_DIR` once at module load to its canonical real path using `fs.realpathSync.native()` (Node 9.2+)
2. Constructs the target path with `path.join()` (safer than `path.resolve()` which can discard the base on absolute-path input)
3. Resolves the target path to its real form, catching `ENOENT` errors for nonexistent files
4. Uses `path.relative(realReportsDir, realTargetPath)` to verify containment — rejects if the relative path is exactly `..`, starts with `.. + separator`, or is absolute
5. Only reads the file if validation passes

This closes the traversal vector by ensuring the filesystem resolves symlinks and normalizes relative segments (`.`, `..`) before containment is checked, then verifying the final real path stays within the intended directory.

## Behaviour changes

- Returns 403 (Access Denied) if a path traversal attempt is detected, instead of serving the file
- Returns 404 for nonexistent files (as before), since `realpathSync` throws `ENOENT` on missing files
- Symlinks and relative references in legitimate filenames are now resolved, so a file truly named `..foo` inside `REPORTS_DIR` remains accessible; a symlink inside the directory pointing outside it is now blocked
