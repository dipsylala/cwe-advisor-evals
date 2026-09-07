## Verdict

exploitable

## Source

User-supplied `reportName` from `req.body.reportName` (line 11), passed directly into shell command string on line 20.

## Fix

**Vulnerable code:**
```javascript
const { exec } = require('child_process');
// ...
exec(`"${scriptPath}" ${reportName}`, (error, stdout, stderr) => {
```

**Fixed code:**
```javascript
const { execFile } = require('child_process');
// ...
if (reportName.startsWith('-')) {
  return res.status(400).send('Invalid reportName');
}

execFile(scriptPath, [reportName], { shell: false }, (error, stdout, stderr) => {
```

## Explanation

The vulnerability arises because `reportName` is interpolated directly into a command string passed to `exec()`, which invokes a shell. An attacker can supply shell metacharacters (e.g., `; rm -rf /` or `&& malicious-command`) to break out of the intended argument and execute arbitrary commands. The fix eliminates shell invocation by switching from `exec()` to `execFile()` with an explicit argument array and `shell: false`, which passes the `reportName` as a single argument to the batch file without re-parsing by the shell. Input validation adds a secondary defense layer by rejecting values that start with `-`, which could be misinterpreted as command-line flags by the batch file or any process it spawns (CWE-88 prevention).

## Behaviour changes

None. The fix preserves the original callback signature and output handling. The `execFile()` call with `shell: false` and an argument array prevents shell metacharacter injection while still executing the batch file with the same `reportName` value, maintaining the original contract: error handling, stdout capture, and response transmission remain unchanged.
