## Verdict
OS command injection via unvalidated user input interpolated into a shell command string. The batch script path is safe, but the `reportName` parameter from `req.body` is passed directly to `exec()`, allowing attackers to inject shell metacharacters like `&`, `|`, `>` to execute arbitrary commands.

## Source
Line 20: `exec()` concatenates untrusted `reportName` directly into a shell command string without escaping or validation.

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

  // Validate reportName to prevent command injection via shell metacharacters
  if (!/^[a-zA-Z0-9_-]+$/.test(reportName)) {
    return res.status(400).send('reportName contains invalid characters');
  }

  const scriptPath = path.join(__dirname, 'scripts', 'generate-report.bat');

  // Use execFile instead of exec to avoid shell interpretation of arguments.
  // Pass arguments as an array; they are never split or interpreted by a shell.
  execFile('cmd.exe', ['/c', scriptPath, reportName], (error, stdout, stderr) => {
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
The fix uses two complementary defenses:

1. **Input validation**: A regex allowlist restricts `reportName` to alphanumeric characters, underscores, and hyphens. This rejects shell metacharacters (`&`, `|`, `>`, `<`, `;`, backticks, `$()`, etc.) before they reach the command layer.

2. **No shell invocation**: Changed from `exec()` to `execFile()`. The `exec()` function spawns a shell and parses the command string, allowing shell syntax injection. `execFile()` passes arguments directly to the target process without shell parsing. Arguments are passed as an array, not concatenated into a string. To invoke batch files on Windows, `execFile` calls `cmd.exe` with `/c` to execute the batch file, and the reportName is passed as a separate argument that `cmd.exe` receives as a literal value, not as part of the shell command line.

Together, these controls prevent an attacker from injecting shell commands through `reportName`.
