## Verdict

Exploitable

## Source

`req.query.domain` (line 8) — untrusted HTTP query parameter

## Fix

**Vulnerable code (line 2 and line 15):**

```javascript
const { exec } = require('child_process');
...
exec(`whois ${domain}`, (error, stdout, stderr) => {
```

**Fixed code:**

```javascript
const { execFile } = require('child_process');
...
if (domain.startsWith('-')) {
  return res.status(400).send('Invalid domain name');
}

execFile('whois', [domain], (error, stdout, stderr) => {
```

## Explanation

The vulnerability allows OS command injection because the `domain` parameter is directly interpolated into a command string passed to `exec()`, which by default spawns a shell interpreter. An attacker can inject shell metacharacters (`|`, `;`, `$()`, etc.) to execute arbitrary commands. The fix replaces `exec()` with `execFile()`, which does not spawn a shell and passes the domain as a separate argument in an array, preventing shell metacharacter injection. The input validation (rejecting domains starting with `-`) addresses argument injection (CWE-88), preventing the domain from being interpreted as an option flag to the whois command itself.

## Behaviour changes

- Import statement changes from `exec` to `execFile`: required for the fix, same API family
- Shell invocation eliminated: `execFile()` does not spawn a shell interpreter, so the whois command receives the domain as a literal argument string, not subject to shell parsing
- Input validation added (domain cannot start with `-`): prevents option injection to whois command; rejects a narrow class of valid-looking but potentially malicious domain inputs
- Callback signature unchanged: `execFile()` uses the same `(error, stdout, stderr)` callback as `exec()`, so the error handling and response logic remain identical
- Return value preserved: both APIs produce the same stdout output, so the caller receives the same result

## Verification

**Syntax check:** `node --check` on fixed code — passed. All imports (`express`, `child_process.execFile`) are standard Node.js APIs. The `execFile()` method signature and callback pattern match the standard child_process module contract. No external dependencies or new APIs beyond standard library were introduced.
