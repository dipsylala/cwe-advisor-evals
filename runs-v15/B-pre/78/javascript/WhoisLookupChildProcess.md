## Verdict

**Confirmed.** Untrusted user input from `req.query.domain` is directly concatenated into a shell command executed by `child_process.exec()`, enabling OS command injection. An attacker can inject arbitrary shell metacharacters and commands by crafting a malicious query parameter.

## Source

`req.query.domain` (line 8) — HTTP query parameter, attacker-controlled, passed without validation to the command sink.

## Fix

Replace `child_process.exec()` with the `whois` npm package, eliminating the shell execution sink entirely.

**Updated code:**

```javascript
const express = require('express');
const whois = require('whois');

const app = express();

app.get('/whois', (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).send('domain query parameter is required');
  }

  whois.lookup(domain, (error, data) => {
    if (error) {
      return res.status(500).send('whois lookup failed');
    }
    res.type('text/plain').send(data);
  });
});

app.listen(3000);

module.exports = app;
```

**Dependency:** Add `whois` to `package.json`:
```json
"whois": "^0.11.5"
```
(Verify the latest stable version against npm before deployment.)

## Explanation

The fix eliminates the OS command injection vulnerability by removing the `child_process.exec()` call entirely and replacing it with the dedicated `whois` npm package. This approach is preferred over parameterized shell execution because it:

1. **Removes the shell interpreter** — No shell is involved, so shell metacharacters and command separators in the input cannot escape the intended operation.
2. **Uses a purpose-built library** — The `whois` package handles the protocol details and domain validation internally, isolating the input from system command construction.
3. **Preserves functionality** — The library returns WHOIS record data that is sent to the HTTP response, maintaining the original endpoint behavior.

The `domain` variable no longer reaches any OS command sink, closing the injection point entirely.

## Behaviour changes

1. **Dependency added:** The code now requires the `whois` npm package; it must be installed via `npm install whois`.
2. **Error handling:** The library may return different error messages or error types than the shell command; the application treats all errors uniformly as 500 responses, so this difference is transparent to the API caller.
3. **Response format:** The raw WHOIS output from the library is returned as-is, matching the original behavior (stdout of the `whois` system command).
4. **Response time:** Library-based lookup may differ slightly from shell invocation, but should be comparable for typical use cases.

No other logic or return values change.
