## Verdict

Exploitable. The `reportName` parameter flows directly from user-controlled HTTP request body into an `exec()` command string without validation or escaping, allowing shell metacharacter injection.

## Source

`req.body.reportName` — user-controlled HTTP POST request body with only a null check, no validation.

## Fix

### File: ExecWindowsBatchTarget.js

```javascript
const express = require('express');
const path = require('path');
const { execFile } = require('child_process');

const app = express();

// Kicks off the bundled Windows batch script that renders a named report
// template into the shared output folder. The .bat lives alongside this
// module so operators can tweak the rendering steps without touching code.
app.post('/reports/generate', (req, res) => {
  const reportName = req.body.reportName;

  if (!reportName) {
    return res.status(400).send('reportName is required');
  }

  const scriptPath = path.join(__dirname, 'scripts', 'generate-report.bat');

  // Use execFile() with argument array to prevent OS command injection.
  // reportName becomes a separate argument element and cannot be interpreted
  // as shell syntax, eliminating the injection vector.
  execFile(scriptPath, [reportName], { shell: false }, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send('report generation failed');
    }
    res.type('text/plain').send(stdout);
  });
});

app.listen(3000);

module.exports = app;
```

## Explanation

The original code passed both the script path and the user-supplied `reportName` as a single concatenated string to `exec()`, which invokes the command through a shell interpreter. This allows an attacker to inject shell metacharacters (e.g., `; rm -rf /` or `&& curl attacker.com`) via `reportName` to execute arbitrary commands.

The fix replaces `exec()` with `execFile()`, which takes the executable path and arguments as separate array elements. When `reportName` is passed as a distinct argument array element with `shell: false`, it cannot be interpreted as shell syntax — it is passed to the target program as-is. The callback structure, return value handling, and error behavior all remain identical to the original.

## Behaviour changes

None. The fix preserves the original sink contract:
- Returns stdout via the callback (same as `exec()`)
- Error handling is unchanged
- No additional parameters are supplied or omitted
- No transformation of the reportName value occurs before passing to the script
- Import changed from `exec` to `execFile` (both from `child_process` standard library)
- Added explicit `shell: false` option (this is the default for `execFile()`, so it is clarifying rather than changing behavior)
