## Verdict

exploitable

## Source

`req.query.domain` (line 8) — untrusted user input from HTTP query parameter passed directly into an OS command string.

## Sink

`child_process.exec()` at line 15 — executes the unsanitized domain value within a shell-interpreted command string, allowing command injection.

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

  // Fixed: Use execFile with argument array and no shell to prevent command injection.
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

The vulnerability arises from concatenating untrusted user input directly into a shell command string (`exec(\`whois ${domain}\`)`). An attacker can inject shell metacharacters or commands via the domain parameter—for example, `domain=example.com; rm -rf /` would execute arbitrary code. The fix replaces `exec()` with `execFile()`, which accepts an argument array where the domain becomes a separate argument rather than part of a shell-interpreted string. This eliminates the injection vector because the domain value is passed directly to the `whois` executable without shell parsing, even if it contains special characters. The command is invoked with `shell: false` (the default for `execFile`), preventing shell metacharacter interpretation entirely.

## Behaviour changes

- Changed from `child_process.exec()` to `child_process.execFile()`: This changes the execution model from shell interpretation to direct program invocation.
- Changed from string template `` `whois ${domain}` `` to argument array `[domain]`: The domain is now a separate argument, not part of a command string. This is the critical security fix that prevents shell injection.
- Import statement changed from `const { exec }` to `const { execFile }`: Only the required function is imported. The rest of the code—callback signature, error handling, response format—remains identical.
- No changes to the callback, return values, or output behavior: The function still passes `stdout` to the response, maintaining the original contract.

## Verification

Syntax check with `node --check` passed without errors. The fixed code uses only standard Node.js APIs (`express`, `child_process.execFile`) that are present in all modern Node.js versions. The `execFile()` method and its callback signature are unchanged from Node.js LTS versions, and the argument array format is the standard way to pass parameters safely to spawned processes in Node.js.

## Assumptions

The `whois` command is assumed to be available on the system PATH or as an absolute path; if it is not available at runtime, `execFile()` will fail with an `ENOENT` error and the 500 response will be returned to the client. This is the same behavior as the original code and is correct for the error case. No validation beyond the empty-string check is required because domain names are legitimate input to the `whois` program and do not pose a flag-injection risk (CWE-88) given that `whois` does not interpret leading hyphens as option indicators for its domain argument.
