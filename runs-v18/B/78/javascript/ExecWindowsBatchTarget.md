## Verdict

Exploitable. The `reportName` parameter from `req.body.reportName` is untrusted user input that is directly concatenated into the command string passed to `exec()`. An attacker can inject arbitrary shell commands. For example, an input like `report.txt"; net user attacker password /add; echo "` would execute the batch script followed by arbitrary commands to create a user account.

## Source

`reportName` from `req.body.reportName` in the POST request body (untrusted user input).

## Fix

The vulnerability exists at line 20 where `exec()` is used with string concatenation of the untrusted `reportName` parameter. The fix replaces `exec()` with `execFile()`, which does not invoke a shell by default, and passes the arguments as an array instead of concatenating them into a command string.

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

  // Fixed: Use execFile with argument array instead of exec with string concatenation
  // execFile defaults to shell: false, preventing shell injection
  // Arguments are passed as an array, so reportName is not interpreted by the shell
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

The original code used `exec()` to run a command constructed by string concatenation, which is vulnerable to shell injection. `exec()` defaults to `shell: true`, meaning the command string is interpreted by a shell where special characters like `;`, `&`, `|`, and `$()` have metacharacter meaning. By injecting these characters, an attacker can chain arbitrary commands.

The fix replaces `exec()` with `execFile()`, which defaults to `shell: false` and takes arguments as an array rather than a command string. This means the `reportName` argument is passed directly to `cmd.exe` without shell interpretation, making it impossible to inject shell commands. The command executes `cmd.exe` with `/c` (to run a command and exit), the batch file path as the next argument, and the report name as a final argument—none of which is subject to shell metacharacter interpretation.

## Behaviour changes

- **Import change**: Changed from importing `exec` to importing `execFile`
- **Shell execution**: Changed from implicit `shell: true` (in `exec()`) to explicit `shell: false` (default in `execFile()`)
- **Argument passing**: Changed from string concatenation (`\`"${scriptPath}" ${reportName}\``) to argument array (`['/c', scriptPath, reportName]`)
- **Process invocation**: Invokes `cmd.exe` explicitly with `/c` flag to execute the batch file, ensuring Windows batch file semantics work correctly
- **Output contract preserved**: The callback still receives `error`, `stdout`, and `stderr` in the same way; the response behavior is unchanged—`stdout` is returned to the client on success, an error message on failure
