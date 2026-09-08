## Verdict

Real CWE-78 OS Command Injection vulnerability. The `exec()` function spawns a shell interpreter, allowing shell metacharacters in the unsanitized `reportName` parameter to break out and execute arbitrary commands.

## Source

Line 20 of ExecWindowsBatchTarget.js:

```javascript
exec(`"${scriptPath}" ${reportName}`, (error, stdout, stderr) => {
```

The `reportName` originates from `req.body.reportName` (line 11) with only a null check, no escaping. When passed to `exec()`, any special characters (`&`, `|`, `;`, `$()`, etc.) are interpreted by the shell, enabling command injection.

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

  // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
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

The fix replaces `exec()` with `execFile()` and passes the batch file and arguments separately. The `execFile()` function does not spawn a shell; instead, it directly executes the specified file with the arguments as an array. This means shell metacharacters in `reportName` are treated as literal argument content, not as command syntax, eliminating the injection vector.

The Windows batch file receives `reportName` as a positional argument (`%1` in the .bat file), exactly as provided by the user, without shell interpretation. No escaping or validation of the value is necessary when using this approach.
