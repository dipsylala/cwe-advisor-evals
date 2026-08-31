## Verdict
Confirmed OS command injection vulnerability on line 15.

## Source
The `domain` parameter from user input (`req.query.domain`) is directly interpolated into the shell command string passed to `exec()` without escaping or validation:

```javascript
exec(`whois ${domain}`, (error, stdout, stderr) => {
```

An attacker can inject shell metacharacters (e.g., `;`, `$(...)`, `` ` ``, `|`, `&`) through the `domain` query parameter to execute arbitrary commands on the server.

## Fix
Replace `exec()` with `execFile()` and pass command arguments as an array instead of interpolating into a string. This prevents shell interpretation of the user-supplied input:

```javascript
const { execFile } = require('child_process');

app.get('/whois', (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).send('domain query parameter is required');
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
The vulnerability exists because `exec()` spawns a shell to interpret the command string, allowing shell metacharacters in user input to alter the executed command. By using `execFile()` with arguments passed as an array, the `whois` binary is invoked directly without a shell, and the `domain` value is passed as a literal argument. This ensures that shell metacharacters are treated as data rather than shell syntax, preventing command injection.
