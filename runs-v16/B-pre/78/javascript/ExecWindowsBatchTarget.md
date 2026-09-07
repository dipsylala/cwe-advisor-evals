## Verdict
CONFIRMED - Real OS command injection vulnerability

## Source
Untrusted input from `req.body.reportName` (line 11) flows directly into the shell command at line 20. The value originates from user-supplied request body data.

## Fix

**Vulnerable code (line 20):**
```javascript
exec(`"${scriptPath}" ${reportName}`, (error, stdout, stderr) => {
```

**Fixed code:**
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

  // Validate reportName: reject anything except alphanumeric, underscore, and hyphen
  if (!/^[a-zA-Z0-9_-]+$/.test(reportName)) {
    return res.status(400).send('invalid reportName');
  }

  const scriptPath = path.join(__dirname, 'scripts', 'generate-report.bat');

  // Use execFile with argument array to prevent command injection;
  // the argument is passed separately from the command, not interpolated into a shell command string
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

The original code uses `exec()`, which spawns a shell (cmd.exe on Windows) to interpret a concatenated command string. This allows an attacker to inject arbitrary shell commands by providing metacharacters in the reportName parameter. For example, a reportName of `"; del /S *; "` would result in the deletion command being executed.

The fix replaces `exec()` with `execFile()`, which executes the batch file directly with arguments passed as an array rather than concatenated into a shell command string. The reportName is now passed as a separate argument that is not subject to shell parsing. Additionally, input validation uses a strict allowlist of safe characters (alphanumeric, underscore, hyphen) to reject values that could bypass this protection or introduce unexpected behavior. Together, these changes eliminate the injection vector while preserving the original functionality for legitimate report names.

## Behaviour changes

- Command execution no longer occurs through shell interpretation
- The reportName parameter is passed to the batch file as a separate argument, not as part of a command string
- Input validation now rejects reportName values containing characters outside the allowed set, returning a 400 error instead of attempting execution
- For valid report names matching the allowlist pattern, functionality remains identical to the original code
