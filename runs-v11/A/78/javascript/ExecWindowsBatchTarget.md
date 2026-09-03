## Verdict

This is a confirmed CWE-78 OS Command Injection vulnerability. The `reportName` parameter from the request body is directly interpolated into a shell command without any sanitization or escaping, allowing an attacker to inject arbitrary shell commands.

## Source

Line 20 in ExecWindowsBatchTarget.js:

```javascript
exec(`"${scriptPath}" ${reportName}`, (error, stdout, stderr) => {
```

The vulnerability is that `reportName` (derived from untrusted user input via `req.body.reportName`) is interpolated directly into the command string. Although `scriptPath` is quoted, `reportName` is not, allowing shell metacharacters to be interpreted as commands rather than as arguments to the batch script.

## Fix

Replace `exec()` with `execFile()` and pass the argument as an array element, preventing shell interpretation:

**Before:**
```javascript
const { exec } = require('child_process');
...
exec(`"${scriptPath}" ${reportName}`, (error, stdout, stderr) => {
```

**After:**
```javascript
const { execFile } = require('child_process');
...
execFile(scriptPath, [reportName], (error, stdout, stderr) => {
```

## Explanation

`exec()` spawns a shell and interpolates the entire command string, causing the shell to parse and interpret special characters in the arguments. `execFile()` directly executes the program file without spawning a shell, and passes arguments as an array where each element is treated as a literal value rather than shell syntax. This design prevents the injection vector by eliminating shell interpretation of user-controlled input entirely, rather than relying on escaping or validation logic that may be incomplete.

