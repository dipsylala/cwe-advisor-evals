## Verdict

This is a confirmed OS command injection vulnerability. The `exec()` function on line 15 passes an unsanitized query parameter directly into a shell command string, allowing an attacker to inject arbitrary shell commands.

## Source

The vulnerability is on line 15:

```javascript
exec(`whois ${domain}`, (error, stdout, stderr) => {
```

The `domain` parameter comes from `req.query.domain` (line 8) without any validation or sanitization. An attacker can inject shell metacharacters (`;`, `|`, `&&`, `||`, `$()`, backticks, etc.) to execute arbitrary commands on the server.

## Fix

Replace `exec()` with `execFile()` and pass the domain as an argument in an array instead of interpolating it into a shell command string:

```javascript
const express = require('express');
const { execFile } = require('child_process');

const app = express();

app.get('/whois', (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).send('domain query parameter is required');
  }

  execFile('whois', [domain], (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send('whois lookup failed');
    }
    res.type('text/plain').send(stdout);
  });
});

app.listen(3000);

module.exports = app;
```

## Explanation

The core fix is switching from `exec()` to `execFile()` and using an argument array. This is the primary defence for OS command injection in Node.js child_process APIs:

- `exec()` spawns a shell (`/bin/sh` on Unix or `cmd.exe` on Windows) and passes the command string to it. Shell metacharacters in the string are interpreted, allowing command chaining and substitution.
- `execFile()` directly spawns the target executable (`whois`) without invoking a shell. Arguments passed in an array are treated as literal operands, not shell syntax. The user-supplied `domain` value cannot be interpreted as shell metacharacters or options, regardless of its content.

This approach eliminates the injection vector entirely while maintaining the same functionality—the whois lookup still receives the domain name as an argument, exactly as intended.
