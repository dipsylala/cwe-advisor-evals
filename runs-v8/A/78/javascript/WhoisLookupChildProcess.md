## Verdict
Confirmed OS Command Injection via unsanitized user input in shell command.

## Source
Line 8: `const domain = req.query.domain;` — user-controlled domain parameter from HTTP query string passes directly to a command execution sink with no validation.

## Fix
Replace `exec()` with `execFile()` and pass the domain as an argument in an array, preventing shell interpretation:

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
The original code uses `exec()`  with template literal interpolation, which passes the command string to a shell for parsing. An attacker supplying `example.com; rm -rf /` as the domain parameter causes both `whois example.com` and `rm -rf /` to execute.

`execFile()` directly spawns the target process (`whois`) without invoking a shell, and passes arguments as an array rather than concatenating them into a string. Shell metacharacters like `;`, `|`, `&`, and `$()` are treated as literal argument values, not command separators or substitution syntax. The `domain` value is safely passed as a single operand to the `whois` program, regardless of its content.
