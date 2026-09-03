## Verdict

Exploitable. The `reportName` parameter from the HTTP request body is directly interpolated into a shell command string passed to `exec()`, allowing arbitrary OS command execution.

## Source

Line 11: `const reportName = req.body.reportName;`

Untrusted user input from the HTTP request body.

## Fix

**Vulnerable Code (Line 20):**
```javascript
exec(`"${scriptPath}" ${reportName}`, (error, stdout, stderr) => {
```

**Fixed Code:**
```javascript
const { execFile } = require('child_process');

// ... inside the route handler:

// Validate reportName against allowlist pattern
if (!reportName || !/^[a-zA-Z0-9._-]+$/.test(reportName)) {
  return res.status(400).send('Invalid report name format');
}

execFile(scriptPath, [reportName], (error, stdout, stderr) => {
  if (error) {
    return res.status(500).send('report generation failed');
  }
  res.type('text/plain').send(stdout);
});
```

## Explanation

The fix eliminates the shell injection vulnerability through three changes. First, it replaces `exec()` with `execFile()`, which does not invoke a shell interpreter and passes arguments as a separate array rather than interpolating them into a command string. Second, it validates `reportName` against a strict allowlist pattern (`^[a-zA-Z0-9._-]+$`) that permits only safe characters used in typical filenames and report names, rejecting any input containing shell metacharacters, quotes, or special symbols. Third, `reportName` is passed as a separate array element to `execFile()` rather than being interpolated, preventing the string from being re-parsed as shell syntax. This combination blocks command injection attacks that rely on embedding shell operators (such as `&`, `|`, `;`) or escaping quotes to break out of the command string.

## Behaviour changes

**Input validation added:** The endpoint now rejects report names containing characters outside the pattern `[a-zA-Z0-9._-]`, returning HTTP 400. Report names previously accepted (e.g., containing spaces or special characters) will be rejected. Reason: allowlist-based validation is required as the primary defence against CWE-88 (argument injection) and CWE-78 when calling external programs on Windows, where batch file arguments are re-parsed by `cmd.exe` at the system level.

**Function change from `exec()` to `execFile()`:** The callback signature remains identical (`(error, stdout, stderr)`), so the error handling and response logic are unchanged. Reason: `execFile()` provides parameterized argument passing without shell interpretation, closing the injection surface.

**Node.js module import change:** `execFile` is now explicitly imported from `child_process` alongside or instead of `exec`. Reason: supports the parameterized API for safe command execution.
