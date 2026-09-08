## Verdict

**Path Traversal vulnerability confirmed and fixed.**

The `res.sendFile()` call on line 22 receives an unsanitized path constructed from `req.query.file`. Without the `root` option, Express does not validate that the resolved path stays within the intended `reportsDir` directory, allowing an attacker to use traversal sequences like `../` to access files outside the intended directory.

## Source

File: ExpressSendFileNoRootOption.js, line 22

```javascript
const reportPath = path.join(reportsDir, requestedFile);
res.sendFile(reportPath);
```

The vulnerability is that `reportPath` is constructed from untrusted user input (`req.query.file`) and passed to `res.sendFile()` without the `root` option. Express does not perform path containment validation on the first argument when `root` is absent.

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

  // SAST FINDING: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) reported here. Sink is the next statement.
  res.sendFile(requestedFile, { root: reportsDir });
});

module.exports = router;
```

## Explanation

The fix uses the `root` option in `res.sendFile()`, which is Express's built-in containment mechanism for path traversal prevention. When the `root` option is set:

1. The first argument (`requestedFile`) is treated as a relative path
2. Express internally resolves it against the base directory (`reportsDir`)
3. Express validates that the resolved path stays within the `root` directory
4. Any attempt to traverse outside (e.g., `../../../etc/passwd`) is blocked

This approach is preferable to manual path validation because it delegates the containment check to the framework, which has already canonicalized and validated the path before performing the file operation. The Express documentation explicitly states that with `root` set, Express validates that the file resolves inside `root`, making this the framework's own containment mechanism for this vulnerability class.

