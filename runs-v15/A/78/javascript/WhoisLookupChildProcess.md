## Verdict
OS command injection vulnerability confirmed. User-supplied `domain` parameter is directly interpolated into a shell command string passed to `exec()`, allowing an attacker to inject arbitrary shell metacharacters and execute commands.

## Source
Line 15: `exec(`whois ${domain}`, ...)`

The `domain` value originates from `req.query.domain` (line 8) without validation or sanitization before being embedded in the command string.

## Fix
Replace `exec()` with `execFile()` and pass the domain as a separate argument:

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
The `execFile()` function directly spawns the `whois` program without invoking a shell, passing the domain as a separate argument in the array `[domain]`. This prevents the shell from interpreting special characters in the domain string—an attacker cannot use `; `, `| `, `&& `, or other shell metacharacters to inject additional commands. The `whois` program receives the domain as a literal argument value, not as part of a shell command string.
