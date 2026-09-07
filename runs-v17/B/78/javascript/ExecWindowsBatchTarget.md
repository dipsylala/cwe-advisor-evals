## Verdict

The finding is confirmed as a real exploitable vulnerability. The untrusted `reportName` parameter from `req.body` is concatenated directly into a shell command string passed to `child_process.exec()`, enabling OS command injection.

## Source

File: `ExecWindowsBatchTarget.js`, line 11-20

- **Input source**: `req.body.reportName` (untrusted HTTP request body)
- **Validation**: Only checks for presence (non-empty), not content
- **Data flow**: Flows directly from source to sink without sanitization
- **Sink**: `exec()` call at line 20 with string concatenation

Exploit vector: An attacker can send `reportName: "test\" & del /s C:\\" (or equivalent for the target system) to execute arbitrary commands after the batch file, or inject cmd.exe metacharacters like `|`, `&`, `>`, or `&&` to chain commands.

## Fix

### File: ExecWindowsBatchTarget.js

```javascript
const express = require('express');
const path = require('path');
const { execFile } = require('child_process');

const app = express();

app.post('/reports/generate', (req, res) => {
  const reportName = req.body.reportName;

  if (!reportName) {
    return res.status(400).send('reportName is required');
  }

  // Validate reportName against strict allowlist - only alphanumeric, underscore, hyphen
  if (!/^[a-zA-Z0-9_-]+$/.test(reportName)) {
    return res.status(400).send('Invalid reportName');
  }

  const scriptPath = path.join(__dirname, 'scripts', 'generate-report.bat');

  // Use execFile with cmd.exe and argument array to safely invoke the batch file
  // Arguments are passed as separate array elements, preventing shell metacharacter injection
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

The vulnerable code used `child_process.exec()` with string concatenation, which invokes a shell and re-parses the concatenated command string. An attacker can inject shell metacharacters into `reportName` to break out of the intended command and execute arbitrary commands.

The fix replaces `exec()` with `execFile()`, which does not invoke a shell and passes arguments as a separate array. This prevents shell metacharacter injection at the sink level. The command is now: `cmd.exe /c "path\to\script.bat" "reportName"`, where `reportName` is a single argument isolated from shell parsing.

Additionally, a strict allowlist validation (`/^[a-zA-Z0-9_-]+$/`) is applied to `reportName` before it reaches the sink. This provides defense-in-depth: even if `execFile()` were bypassed or misused elsewhere, the value cannot contain shell metacharacters, command separators, or flag prefixes. The validation rejects the input early and explicitly, preventing injection vectors like `"test" & cmd.exe` or `test | cat /etc/passwd`.

The fix preserves the original code's return behavior (stdout is sent to the response) and error handling, ensuring no regression in functionality.

Verification: Syntax checked with `node --check` and passes without errors. The `execFile()` API and argument array form are standard Node.js APIs available in all supported versions. The allowlist regex ensures only safe characters reach the underlying process.

## Behaviour changes

- **Rejection of invalid reportName**: Requests with report names containing characters outside [a-zA-Z0-9_-] now receive a 400 response instead of being processed. This is an intentional security boundary.
- **Shell parsing eliminated**: The command is no longer parsed by cmd.exe, eliminating all shell metacharacter injection vectors. Side effects: any legitimate report names that relied on shell escaping or special characters will now be rejected. Operators must use only alphanumeric names, underscores, or hyphens.
- **No change to success path**: Valid report names continue to execute the batch file and return stdout exactly as before.
