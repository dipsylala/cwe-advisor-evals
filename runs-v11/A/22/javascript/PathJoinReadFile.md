## Verdict

Path traversal vulnerability confirmed. Unsanitized user input from `req.query.file` flows directly to `fs.readFile()` via `path.join()`, allowing directory escape through sequences like `../../etc/passwd`.

## Source

Line 10: `const fileName = req.query.file;`

User input from the query parameter is not validated to ensure it remains within the intended `REPORTS_DIR`.

## Fix

Add a validation check after constructing `targetPath` to ensure the resolved path stays within `REPORTS_DIR`:

```javascript
const targetPath = path.join(REPORTS_DIR, fileName);

// Resolve both paths to absolute and verify targetPath is within REPORTS_DIR
const resolvedTarget = path.resolve(targetPath);
const resolvedBase = path.resolve(REPORTS_DIR);

if (!resolvedTarget.startsWith(resolvedBase + path.sep) && resolvedTarget !== resolvedBase) {
  return res.status(403).send('Access denied');
}

fs.readFile(targetPath, 'utf8', (err, data) => {
  // ... rest of handler
});
```

## Explanation

`path.join()` performs string concatenation without validation; it resolves `.` and `..` but does not enforce directory boundaries. An attacker passing `../../../etc/passwd` will traverse outside the intended directory.

The fix uses `path.resolve()` to convert both paths to absolute form, then verifies the target's resolved path starts with the base directory path (plus the separator) or equals it exactly. This prevents directory escape while preserving legitimate access to files within `REPORTS_DIR` and its subdirectories.
