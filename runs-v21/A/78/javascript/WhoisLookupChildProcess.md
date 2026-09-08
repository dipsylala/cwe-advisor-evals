## Verdict

The code is vulnerable to OS command injection on line 15. The `domain` parameter is interpolated directly into a shell command string passed to `exec()`, allowing attackers to inject arbitrary commands (e.g., `example.com; rm -rf /`).

## Source

Line 15 uses `exec()` with a template literal:
```javascript
exec(`whois ${domain}`, (error, stdout, stderr) => {
```

The `domain` comes from untrusted user input (`req.query.domain` from line 8) and is passed to a shell without escaping or argument isolation.

## Fix

### File: WhoisLookupChildProcess.js

```javascript
const express = require('express');
const { execFile } = require('child_process');

const app = express();

// Looks up WHOIS registration details for a domain the caller wants to check.
app.get('/whois', (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).send('domain query parameter is required');
  }

  // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
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

The fix replaces `exec()` with `execFile()` and passes the domain as a separate argument in an array. This prevents the shell from interpreting special characters in the domain value as command separators or operators. The `execFile()` function does not spawn a shell—it directly executes the `whois` program with the domain as an argument, closing the injection vector.

Key changes:
- Import `execFile` instead of `exec` (line 2)
- Pass domain as an array argument to `execFile()` (line 16)
- No template literal or string concatenation
