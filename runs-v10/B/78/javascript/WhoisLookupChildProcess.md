## Verdict

Exploitable. The `domain` query parameter flows directly into the shell command string passed to `exec()`, enabling OS command injection.

## Source

`req.query.domain` (line 8): attacker-controlled HTTP query parameter.

## Fix

**Vulnerable code:**
```javascript
exec(`whois ${domain}`, (error, stdout, stderr) => {
  if (error) {
    return res.status(500).send('whois lookup failed');
  }
  res.type('text/plain').send(stdout);
});
```

**Fixed code:**
```javascript
const { execFile } = require('child_process');

// Validate domain format to reject argument injection attempts
const domainRegex = /^[a-zA-Z0-9.-]+$/;
if (!domainRegex.test(domain)) {
  return res.status(400).send('invalid domain format');
}

execFile('whois', [domain], { shell: false }, (error, stdout, stderr) => {
  if (error) {
    return res.status(500).send('whois lookup failed');
  }
  res.type('text/plain').send(stdout);
});
```

## Explanation

The fix uses `execFile()` instead of `exec()` and passes the domain as a separate argument in an array. This prevents the shell from interpreting special characters in the domain value. The `shell: false` option explicitly disables shell processing. Additionally, input validation using a strict allowlist regex rejects domains containing characters that could be interpreted as shell metacharacters or command-line flags, providing a secondary defence layer against both shell injection and argument injection attacks.

## Behaviour changes

- Import statement added: `const { execFile } = require('child_process');` — required to access the safe API.
- Input validation added: strict allowlist regex checks domain format before execution — rejects values with special characters or flag-like patterns, preventing injection attempts.
- Function changed from `exec()` to `execFile()` — `execFile()` bypasses shell parsing entirely by passing the command and arguments separately to the OS.
- Argument passing changed from string interpolation to array form — the domain is now a separate element in `[domain]` rather than interpolated into a shell string.
- `shell: false` option explicitly set — ensures shell processing is disabled.
