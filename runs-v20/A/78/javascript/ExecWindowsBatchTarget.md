## Verdict

Confirmed. `reportName` comes from the untrusted request body and is concatenated directly into a string passed to `exec()`, which runs it through `cmd.exe`. Any shell metacharacter in the value (`&`, `|`, `^`, `%`, backticks-equivalent, quotes, etc.) lets an attacker chain or replace the intended command.

## Source

`req.body.reportName` in the `POST /reports/generate` handler (`ExecWindowsBatchTarget.js`, line 11) is attacker-controlled HTTP input with no validation before it reaches the sink.

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

  // Report names identify one of a fixed set of bundled templates, so a
  // strict identifier shape is a valid product constraint, not just a
  // security overlay - reject anything outside it before it can reach the
  // spawned process.
  if (!/^[A-Za-z0-9_-]+$/.test(reportName)) {
    return res.status(400).send('reportName is invalid');
  }

  const scriptPath = path.join(__dirname, 'scripts', 'generate-report.bat');

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

The original code built a single command-line string with `exec()`, so `reportName` was parsed by `cmd.exe` along with the intended script invocation - a value such as `report1 & del /Q C:\*` runs as a second, attacker-chosen command.

The fix has two parts:

1. **Sink change**: `exec()` is replaced with `execFile()`, passing `reportName` as a separate array element (`[reportName]`) instead of interpolating it into a command string. `execFile` does not hand the whole line to a shell for parsing the way `exec` does.
2. **Allowlist validation**: because Node's `child_process` internally re-invokes `cmd.exe` for `.bat`/`.cmd` targets on Windows even through `execFile` (a long-standing platform quirk; argument-escaping bugs in that internal path were fixed in Node 18.20.4/20.15.1/21.7.3/22.5.0), argument-array usage alone is not a guaranteed backstop on every Node version. Restricting `reportName` to `^[A-Za-z0-9_-]+$` before it reaches `execFile` removes every shell metacharacter (`&`, `|`, `^`, `%`, quotes, spaces, redirection) from the value regardless of the installed Node patch level, so the fix does not depend on the runtime's internal escaping being correct. This also matches the domain: report names identify a bounded set of known templates, so constraining their shape is a legitimate input contract, not an incidental security-only restriction.

Verification: confirm a request with `reportName` such as `sales & calc` or `sales" ; whoami ; "` is rejected with 400 before invoking `generate-report.bat`, and that a legitimate value (e.g. `sales-2024`) still generates the report and returns its output as before.
