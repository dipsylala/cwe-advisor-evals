## Verdict
Confirmed. The `domain` parameter is directly interpolated into a shell command string and passed to `exec()`, allowing arbitrary command injection.

## Source
Line 15: `exec(`whois ${domain}`, ...)` receives unsanitized user input from `req.query.domain` and interpolates it into the shell command. The `exec()` function spawns a shell, which interprets metacharacters in the command string.

## Fix
Replace `exec()` with `execFile()` and pass the domain as a separate argument array:

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
`execFile()` does not invoke a shell interpreter. It directly executes the command with arguments passed as a separate array. This separates the program name from argument processing, treating each array element as a literal argument value, not a shell expression. Metacharacters like `;`, `|`, `&`, and backticks in the `domain` parameter are no longer interpreted as command separators or substitution operators—they become literal characters in the argument passed to `whois`.
