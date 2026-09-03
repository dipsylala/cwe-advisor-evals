## Verdict

The code is vulnerable to OS command injection via unsanitized concatenation of user input into a shell command string.

## Source

Line 20:
```javascript
exec(`"${scriptPath}" ${reportName}`, (error, stdout, stderr) => {
```

The `reportName` parameter originates from user-controlled input (`req.body.reportName` on line 11) and is directly interpolated into the command string without any validation or escaping. Since `exec()` invokes a shell interpreter, an attacker can inject additional commands using shell metacharacters (e.g., `&`, `;`, `|`, `"`, backticks).

**Attack example:** A malicious `reportName` of `test" & whoami &` would result in executing `whoami` as an additional command in the batch script context.

## Fix

Replace `exec()` with `execFile()` and pass the argument as a separate array element. Also validate the `reportName` to accept only expected characters (e.g., alphanumeric, dash, underscore).

```javascript
const { execFile } = require('child_process');

app.post('/reports/generate', (req, res) => {
  const reportName = req.body.reportName;

  if (!reportName) {
    return res.status(400).send('reportName is required');
  }

  // Validate reportName to allow only safe characters
  if (!/^[a-zA-Z0-9_-]+$/.test(reportName)) {
    return res.status(400).send('Invalid reportName format');
  }

  const scriptPath = path.join(__dirname, 'scripts', 'generate-report.bat');

  // Use execFile with arguments passed as separate array elements
  execFile(scriptPath, [reportName], (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send('report generation failed');
    }
    res.type('text/plain').send(stdout);
  });
});
```

## Explanation

`exec()` spawns a shell interpreter that parses the entire command string, allowing shell metacharacters in arguments to be interpreted as command operators rather than literals. This enables command injection.

`execFile()` executes the target program directly without a shell, treating each array element as a separate argument. Shell metacharacters lose their special meaning and are passed as literal strings to the batch script.

The input validation ensures `reportName` contains only characters that cannot form path traversal sequences or unexpected arguments, providing defense-in-depth.

For Windows batch files, `execFile()` still successfully executes .bat files directly without requiring shell interpretation.
