## Verdict

Confirmed. The `/whois` handler builds a shell command string by interpolating the untrusted `domain` query parameter directly into `exec("whois ${domain}")`. `exec` runs its argument through `/bin/sh -c`, so shell metacharacters in `domain` (e.g. `; rm -rf /`, `$(...)`, backticks, `&&`, `|`) are interpreted by the shell rather than treated as literal text, giving an attacker arbitrary command execution with the privileges of the Node process.

## Source

`req.query.domain` in `app.get('/whois', ...)` (line 8) — an Express query-string parameter, fully attacker-controlled, flows unmodified into the `exec` call at line 15.

## Fix

### File: WhoisLookupChildProcess.js
```javascript
const express = require('express');
const { execFile } = require('child_process');

const app = express();

// A hostname/domain label per RFC 1034/1035: letters, digits, hyphens, dots.
// This is the format the application itself expects for this field, so
// rejecting anything else is a correctness constraint, not just a security bolt-on.
const DOMAIN_PATTERN = /^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+$/;

// Looks up WHOIS registration details for a domain the caller wants to check.
app.get('/whois', (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).send('domain query parameter is required');
  }

  if (typeof domain !== 'string' || !DOMAIN_PATTERN.test(domain)) {
    return res.status(400).send('invalid domain query parameter');
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

`execFile` invokes the `whois` binary directly, with `domain` passed as a discrete argv element — there is no shell involved, so shell metacharacters in `domain` are never interpreted; the `whois` process receives them as inert literal text. This alone closes the command-injection sink.

`execFile` still leaves one narrower gap that a shell string never raised as a concern to begin with: `whois` itself parses its arguments, and a value beginning with `-` (e.g. `-h attacker.example`) could be read by `whois` as a flag rather than a hostname, letting a caller redirect the query to an arbitrary WHOIS server. Because "domain" is a value whose format the application already defines (RFC 1034/1035 hostname syntax — letters, digits, hyphens, and dots, never a leading hyphen as the first character of the whole string), constraining it with `DOMAIN_PATTERN` is validating the field's own contract rather than adding a security-motivated allowlist on top of an already-fixed sink. The pattern rejects anything containing shell metacharacters, whitespace, or a leading `-`, while still accepting ordinary domains, subdomains, and internationalized-domain punycode labels (`xn--...`).

A test that reproduces the original bug should assert that a value such as `example.com; touch /tmp/pwned` (or backticks/`$(...)`) is rejected with 400, and that `whois` never spawns for it — the pre-fix code passed that string straight into `/bin/sh -c whois example.com; touch /tmp/pwned`, so the injected command runs unconditionally regardless of whether the `whois` lookup itself succeeds. A legitimate domain such as `example.com` should still return 200 with WHOIS text in the body, confirming the fix does not regress normal use.
