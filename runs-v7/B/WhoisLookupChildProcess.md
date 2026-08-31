## Verdict

Exploitable. The domain query parameter is passed directly into an `exec()` call without validation or escaping, allowing OS command injection.

## Source

`req.query.domain` at line 8. Untrusted input from HTTP query parameter flows directly to the `exec()` sink without any sanitization.

## Fix

**Vulnerable code (lines 14-21):**
```javascript
exec(`whois ${domain}`, (error, stdout, stderr) => {
  if (error) {
    return res.status(500).send('whois lookup failed');
  }
  res.type('text/plain').send(stdout);
});
```

**Fixed code (using child_process.execFile with argument array):**
```javascript
execFile('whois', [domain], (error, stdout, stderr) => {
  if (error) {
    return res.status(500).send('whois lookup failed');
  }
  res.type('text/plain').send(stdout);
});
```

**Updated imports (line 2):**
```javascript
const { execFile } = require('child_process');
```

Validation should be added to reject inputs that resemble command injections:
```javascript
if (!domain || /[;&|`$(){}[\]<>]/.test(domain)) {
  return res.status(400).send('invalid domain format');
}
```

## Explanation

The fix replaces `exec()` with `execFile()` and uses an argument array rather than string concatenation. The `execFile()` function with separate arguments prevents the shell from interpreting special characters in the domain parameter as command operators. By passing `domain` as a separate element in an array, any characters the attacker supplies are treated as literal argument data, not shell syntax. The import statement is updated to destructure `execFile` instead of `exec`.

## Behaviour changes

- **Function call changed**: `exec()` → `execFile()` with argument array. This passes the domain as a separate argument instead of concatenating it into the command string.
- **Shell interpretation disabled**: `execFile()` defaults to `shell: false`, preventing shell metacharacter interpretation (explicit specification recommended for clarity: add `{ shell: false }` as third parameter for defensive documentation).
- **Input validation added**: A regex check rejects domains containing shell metacharacters (`;&|`$(){}[]<>`), enforcing a whitelist of safe character patterns. This provides defense-in-depth; argument array alone prevents shell injection but not argument injection (CWE-88), so values starting with `-` could still be interpreted as flags by `whois` itself. The validation mitigates this secondary risk.
- **Return behavior preserved**: The callback signature and response handling remain identical to the original - error handling and stdout transmission are unchanged.
- **Stderr still discarded**: Like the original, `stderr` is not used; this is acceptable for this command's context where error status is communicated via the error callback parameter.

**Note**: This is a last-resort fix using parameterized execution. The guidance prefers eliminating the command entirely via a WHOIS npm library if one becomes available; this fix closes the injection while maintaining the same API contract.
