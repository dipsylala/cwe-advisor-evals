## Verdict

The vulnerability is confirmed. Line 15 uses `exec()` with user-controlled input directly interpolated into the command string, allowing arbitrary OS command execution.

## Source

The domain parameter originates from the Express query parameter `req.query.domain` (line 8) and is passed directly to `exec()` without validation, argument array encapsulation, or quoting (line 15). An attacker can inject shell metacharacters and commands by crafting a domain value like `example.com; rm -rf /` to execute arbitrary code with the process's privileges.

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

Replace `exec()` with `execFile()` and pass the user-controlled domain as an argument in an array. `execFile()` does not spawn a shell interpreter and instead directly executes the program with the supplied arguments. Arguments are never interpreted as shell syntax, so metacharacters like `;`, `|`, `&`, `>`, and backticks in the domain value are treated as literal characters passed to the `whois` program, not as command separators or redirects. This eliminates the injection pathway entirely while preserving the intended functionality.

