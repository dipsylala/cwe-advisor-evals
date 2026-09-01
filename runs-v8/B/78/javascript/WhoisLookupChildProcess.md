## Verdict

Exploitable. The `domain` query parameter is directly interpolated into a shell command string passed to `exec()`, allowing arbitrary OS command injection.

## Source

Untrusted user input: `req.query.domain` (line 8) is sourced from the HTTP query string without validation, then concatenated directly into the shell command at line 15.

## Fix

**Vulnerable code:**
```javascript
const { exec } = require('child_process');

app.get('/whois', (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).send('domain query parameter is required');
  }

  exec(`whois ${domain}`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send('whois lookup failed');
    }
    res.type('text/plain').send(stdout);
  });
});
```

**Fixed code:**
```javascript
const { execFile } = require('child_process');

app.get('/whois', (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).send('domain query parameter is required');
  }

  // Validate domain format to prevent flag injection attacks
  if (!/^[a-zA-Z0-9.-]+$/.test(domain)) {
    return res.status(400).send('Invalid domain format');
  }

  execFile('whois', [domain], (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send('whois lookup failed');
    }
    res.type('text/plain').send(stdout);
  });
});
```

## Explanation

The fix eliminates the OS command injection vulnerability by replacing `exec()` with `execFile()` and passing the domain as a separate array argument instead of interpolating it into a shell command string. This prevents the shell from interpreting special characters in the domain parameter as command operators. Additionally, a domain format validation using a strict allowlist regex prevents argument injection attacks (CWE-88) where an attacker could pass a value starting with `-` to manipulate whois command-line flags. The validation ensures only valid domain names (alphanumeric characters, dots, and hyphens) are passed to the whois command.

## Behaviour changes

- **Require change**: Changed `const { exec }` to `const { execFile }` to avoid shell invocation
- **Argument passing**: Changed from string interpolation (`\`whois ${domain}\``) to argument array (`['whois', [domain]]`) — prevents shell metacharacter interpretation
- **New validation**: Added domain format check using regex `/^[a-zA-Z0-9.-]+$/` before command execution — rejects any domain with special characters that could be interpreted as shell operators or command flags
- **Security benefit**: Shell is no longer invoked by default with execFile, eliminating the entire class of shell metacharacter injection attacks
- **Output behavior**: Unchanged — stdout is still returned on success and errors are handled identically
- **Error handling**: Unchanged — error callback behavior remains the same
