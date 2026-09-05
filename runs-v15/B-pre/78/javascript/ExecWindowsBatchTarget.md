## Verdict

Real vulnerability confirmed. Untrusted user input (`reportName` from request body) is directly interpolated into a shell command string passed to `exec()`, enabling OS command injection.

## Source

Line 11: `const reportName = req.body.reportName;` - untrusted HTTP request body parameter  
Line 20: `exec(\`"${scriptPath}" ${reportName}\`, ...)` - sink where injection occurs

Data flow: HTTP request body → reportName variable → unvalidated string interpolation into shell command → exec()

## Fix

Replace the vulnerable `exec()` call with `spawn()` using an argument array to prevent shell interpretation, combined with strict input validation:

```javascript
const express = require('express');
const path = require('path');
const { spawn } = require('child_process');

const app = express();

// Allowlist of valid report template names to prevent injection
const VALID_REPORT_NAMES = new Set(['monthly', 'quarterly', 'annual', 'summary']);

app.post('/reports/generate', (req, res) => {
  const reportName = req.body.reportName;

  if (!reportName) {
    return res.status(400).send('reportName is required');
  }

  // Validate against allowlist and use canonical value
  if (!VALID_REPORT_NAMES.has(reportName)) {
    return res.status(400).send('Invalid report name');
  }

  const scriptPath = path.join(__dirname, 'scripts', 'generate-report.bat');

  // Use spawn() with argument array and shell: false to prevent injection.
  // On Windows, cmd /c is required to invoke batch files safely.
  const proc = spawn('cmd', ['/c', scriptPath, reportName], { 
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe']
  });

  let stdout = '';
  let stderr = '';

  proc.stdout.on('data', (data) => {
    stdout += data;
  });

  proc.stderr.on('data', (data) => {
    stderr += data;
  });

  proc.on('close', (code) => {
    if (code !== 0) {
      return res.status(500).send('report generation failed');
    }
    res.type('text/plain').send(stdout);
  });

  proc.on('error', (error) => {
    return res.status(500).send('report generation failed');
  });
});

app.listen(3000);

module.exports = app;
```

## Explanation

The fix eliminates command injection through two layers:

1. **Parameterized execution**: `spawn()` with an argument array and `shell: false` prevents the shell from interpreting the `reportName` parameter as shell syntax. The operating system passes the argument directly to the batch file without re-parsing.

2. **Input validation**: `reportName` is validated against an allowlist of known valid report templates before use. The canonical value from the allowlist is passed downstream, not the original untrusted input.

The `proc.on()` handlers preserve the original behavior by collecting stdout and returning it in the response on successful completion (exit code 0), and returning a 500 error on failure. Windows batch files require `cmd /c` as the executable with the script path as an argument because the Windows API does not support passing arguments directly to batch files; `spawn()` with `shell: false` ensures cmd.exe does not re-parse the arguments as shell metacharacters.

## Behaviour changes

- `exec()` (shell-enabled subprocess) → `spawn()` with argument array and `shell: false` (no shell interpretation)
- Synchronous callback-based output collection → Event-driven streams with buffering
- Accepts any reportName → Rejects invalid reportName with HTTP 400 response
- Direct return of stdout → Same stdout returned after validation; same error handling on failure
