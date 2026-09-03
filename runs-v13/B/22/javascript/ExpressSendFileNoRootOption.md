## Verdict

Exploitable. An attacker can supply path traversal sequences in the `file` query parameter to read arbitrary files on the filesystem outside the intended `reportsDir` directory.

## Source

User-supplied input from `req.query.file` (line 13), passed unsanitized to `path.join()` and then to `res.sendFile()` without validation.

## Fix

**Vulnerable code (line 19-22):**
```javascript
const reportPath = path.join(reportsDir, requestedFile);

// SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
res.sendFile(reportPath);
```

**Fixed code:**
```javascript
// Removed: const reportPath = path.join(reportsDir, requestedFile);

// SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
res.sendFile(requestedFile, { root: reportsDir });
```

## Explanation

The fix leverages Express's built-in path validation through the `root` option to `res.sendFile()`. When the `root` option is set, Express validates that the resolved path stays within the specified root directory, preventing traversal attacks. The attacker-controlled `requestedFile` is now passed as a relative path to Express, which ensures resolution within `reportsDir` boundaries. According to Node.js Express documentation and CWE-22 JavaScript guidance, this is the framework's own containment mechanism and is preferable to hand-written validation.

## Behaviour changes

- **Path construction removed**: The `path.join(reportsDir, requestedFile)` assignment is eliminated since Express handles path resolution internally when `root` is supplied
- **File operation changes**: `res.sendFile()` now receives the relative filename and root directory separately, rather than a pre-joined absolute path. This is the intended usage pattern for Express's path containment mechanism
- **Security validation added**: Express will now validate that the resolved real path stays within `reportsDir` before opening the file
