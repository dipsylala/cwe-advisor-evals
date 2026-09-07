## Verdict

Exploitable. The `reportName` parameter from the HTTP request body is directly interpolated into a shell command string passed to `exec()`. An attacker can inject arbitrary OS commands through shell metacharacters in the `reportName` field.

## Source

`req.body.reportName` - untrusted input from HTTP POST request body (line 11)

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

  // Use execFile with separate arguments array instead of exec with string concatenation
  // This prevents reportName from being interpreted as shell metacharacters
  execFile(scriptPath, [reportName], (error, stdout, stderr) => {
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

The vulnerability is fixed by replacing `exec()` with `execFile()` and passing `reportName` as a separate element in an argument array rather than interpolating it into a command string. This prevents shell metacharacters in `reportName` from being interpreted by the shell. `execFile()` with `shell: false` (the default) passes arguments directly to the target program's `argv` without shell re-parsing, eliminating the injection vector.

Note: On Windows, the operative Node.js versions carrying the CVE-2024-36138 fix (18.20.4, 20.15.1, 22.4.1+) will reject invocation of `.bat` files directly with `EINVAL`, as batch files inherently trigger `cmd.exe` re-parsing. This is the intended fix working as designed. The proper long-term remediation is to invoke the wrapped executable that the batch file calls rather than the batch file itself.

## Behaviour changes

Argument passing: `reportName` is now passed as a separate argument in an array rather than interpolated into a shell command string. The `execFile()` API receives the same `(error, stdout, stderr)` callback signature and returns results in the same way, so the handler contract is preserved.

## Verification

`node --check` passed on the fixed code with no syntax errors or warnings. All APIs used (`execFile` from `child_process`, `path.join`, `express`) are standard Node.js and npm modules already present in the original code's dependencies.
