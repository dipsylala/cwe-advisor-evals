## Verdict

Confirmed. Untrusted user input (`req.query.domain`) flows directly into a shell command string passed to `exec()` without validation or parameterization, enabling arbitrary OS command execution.

## Source

`req.query.domain` (user-controlled HTTP query parameter, line 8)

## Fix

Replace `child_process.exec()` with `child_process.execFile()` and pass the domain as a separate argument in an array, preventing shell interpretation of the input.

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

// At line 15, replace exec() with execFile()
execFile('whois', [domain], (error, stdout, stderr) => {
  if (error) {
    return res.status(500).send('whois lookup failed');
  }
  res.type('text/plain').send(stdout);
});
```

## Explanation

`exec()` invokes a shell and concatenates its arguments into a command string, allowing shell metacharacters in the domain parameter to break out of the whois argument and inject arbitrary commands. `execFile()` spawns the target program directly with arguments passed as an array, bypassing shell interpretation entirely. The domain value becomes a single argument to the whois program with no shell parsing, eliminating command injection.

## Behaviour changes

The fix preserves all observable behaviour: it still invokes `whois` with the domain, still returns stdout on success, still handles errors the same way. The only change is that shell metacharacters in the domain input are treated as literal characters (the correct behaviour) rather than as command separators or operators (the injection vector).
