## Verdict

REMEDIATED: OS Command Injection vulnerability closed by eliminating shell invocation and passing user input as a separate argument.

## Source

**File**: WhoisLookupChildProcess.js  
**Line**: 8  
**Value**: `req.query.domain` — untrusted domain name from URL query parameter

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

  // Use execFile() with argument array and no shell to prevent command injection.
  // The '--' marker prevents the domain from being interpreted as a flag if it starts with '-'.
  execFile('whois', ['--', domain], (error, stdout, stderr) => {
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

The original code passed user input directly into a shell command string using `child_process.exec()`, which interprets the entire string through the shell. An attacker controlling the `domain` parameter could inject arbitrary shell metacharacters (`;`, `|`, `&`, `$()`, etc.) to execute additional commands on the host.

The fix replaces `exec()` with `execFile()` and passes the domain as a separate argument in an array. `execFile()` does not invoke a shell by default, so shell metacharacters are treated as literal argument text rather than interpreted. The `--` marker before the domain argument tells the whois command to stop processing flags; any domain starting with `-` will be treated as a literal argument value rather than an option flag, preventing option injection (CWE-88).

The remediation preserves the original behavior: the whois command is executed with the domain as its operand, and stdout is returned to the caller in the same response format.

## Behaviour changes

- **Command execution**: Changed from shell-invoked (`exec()`) to direct process execution (`execFile()`)
- **Argument handling**: Domain is now passed as a separate array element rather than concatenated into a string
- **Shell metacharacters**: No longer interpreted by the shell; treated as literal characters
- **Option injection protection**: The `--` marker prevents domains starting with `-` from being interpreted as command flags

The application behavior is functionally identical from the client perspective: the whois lookup still occurs and stdout is returned as before.
