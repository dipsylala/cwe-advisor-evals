## Verdict

Exploitable. Untrusted user input from `req.query.domain` flows directly into a shell command string without validation, allowing arbitrary command injection.

## Source

Line 8: `const domain = req.query.domain;` - HTTP query parameter, untrusted user input with no validation.

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

  // Validate domain to prevent argument injection
  if (!/^[a-zA-Z0-9.-]+$/.test(domain)) {
    return res.status(400).send('Invalid domain format');
  }

  // Use execFile with argument array and no shell to prevent command injection
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

The vulnerability was eliminated by replacing `child_process.exec()` with `execFile()` and passing the domain as a separate argument in an array rather than interpolating it into a command string. This prevents shell metacharacter injection—the command string is never parsed by a shell, and the domain value cannot escape the argument boundary. Additionally, input validation using a strict allowlist regex `^[a-zA-Z0-9.-]+$` rejects values that might be mistaken for command-line flags or contain shell metacharacters, providing defense-in-depth. The fix aligns with the CWE-78 guidance: eliminate the shell interpreter, use parameterized APIs with separate argument arrays, and apply input validation as a secondary layer.

## Behaviour changes

The import changes from `const { exec }` to `const { execFile }`, which is a direct substitution from the child_process module. The `execFile()` API has the same callback signature `(error, stdout, stderr)` as `exec()`, so the error handling and response sending remain unchanged and preserve the original behavior. The domain validation adds an early return for invalid formats, which is a security enhancement that rejects input the original code would have accepted; this is appropriate given the validation only rejects values that pose injection risk. No other changes to program flow, return values, or data handling occur.
