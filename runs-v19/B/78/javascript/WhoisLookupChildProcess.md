## Verdict

Confirmed. The code passes an attacker-controlled domain parameter directly into a shell command string via `exec()`, allowing arbitrary command injection through shell metacharacters.

## Source

`req.query.domain` (line 8) - attacker-controlled query parameter

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

  // Reject domains starting with '-' to prevent argument injection
  if (domain.startsWith('-')) {
    return res.status(400).send('invalid domain');
  }

  // Use execFile with argument array to prevent command injection
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

The vulnerable code concatenated the untrusted `domain` parameter directly into a shell command string (`exec(\`whois ${domain}\`)`), allowing attackers to inject arbitrary shell commands via metacharacters like `;`, `|`, `$()`, etc.

The fix replaces `exec()` with `execFile()`, which executes the whois binary directly without spawning a shell. The domain is passed as a separate array element rather than interpolated into a string, so the shell parser never sees it. The additional validation rejects domains starting with `-` to prevent argument injection (CWE-88), since a malicious value like `-h attacker.com` could be misinterpreted as command flags.

The fix preserves the original contract: the whois output is still returned to the caller.

## Behaviour changes

- The `domain` parameter is no longer interpreted by a shell, closing OS command injection
- Domains starting with `-` are now rejected with a 400 response
- `execFile()` does not inherit the shell environment (PATH, aliases, functions), only standard system programs are available
