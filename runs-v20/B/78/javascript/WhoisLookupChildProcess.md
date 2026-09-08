## Verdict

Confirmed - exploitable. `req.query.domain` reaches `child_process.exec()` through unsanitized string interpolation, so a value like `example.com; rm -rf /` or `example.com $(id)` is executed by the shell.

## Source

`req.query.domain` in the Express handler `app.get('/whois', ...)` (`WhoisLookupChildProcess.js`, line 8).

## Fix

### File: WhoisLookupChildProcess.js

```javascript
const express = require('express');
const { execFile } = require('child_process');

const app = express();

const WHOIS_BIN = '/usr/bin/whois';
// A domain query has to be a dotted sequence of DNS labels (letters, digits,
// hyphens; 1-63 chars each, no leading/trailing hyphen). This also guarantees
// the value cannot start with '-', so it cannot be read as a whois flag.
const DOMAIN_PATTERN = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

// Looks up WHOIS registration details for a domain the caller wants to check.
app.get('/whois', (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).send('domain query parameter is required');
  }

  if (!DOMAIN_PATTERN.test(domain)) {
    return res.status(400).send('domain query parameter is not a valid domain name');
  }

  execFile(WHOIS_BIN, ['--', domain], (error, stdout, stderr) => {
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

The endpoint's purpose is to run the `whois` command, not to wrap something Node already does natively - there is no standard-library or well-maintained npm equivalent that queries the WHOIS protocol, so per the CWE-78 guidance this is a keep-and-execute-safely case, not a delete-the-sink case. Three changes close the injection while preserving that behaviour:

1. **`exec()` -> `execFile()` with an argument array.** `exec()` runs the fully-interpolated string through `/bin/sh -c`, so any shell metacharacter in `domain` (`;`, `|`, `` ` ``, `$()`, etc.) is interpreted by the shell. `execFile()` invokes the `whois` binary directly with an argument array and no shell, so the domain value is passed as a single, literal argv element and metacharacters have no special meaning.
2. **A literal `--` ahead of the domain argument.** An argument array alone stops shell injection but not argument/flag injection (CWE-88): a value starting with `-` could still be read as a whois option rather than a query. `whois`'s option parser (GNU getopt-based) honours `--` as the end-of-options marker, so inserting it rejects nothing legitimate while making the domain position immune to flag injection - the domain-format validation below (which requires the value to start alphanumeric) already excludes a leading `-`, so `--` is a second, independent layer to the same effect.
3. **Domain-format validation as a secondary, application-owned check.** `domain` is documented as a DNS domain name, so a dotted-label pattern (RFC 1035-shaped: alphanumeric/hyphen labels, no leading/trailing hyphen, 1-63 chars per label) is a format the application already owns, not a security-only allowlist. It rejects control characters, spaces, and shell metacharacters along with malformed names; it does not reject anything that is actually a domain name, including internationalized domains in their `xn--` punycode form and bare IP-address-shaped hosts. It intentionally rejects an empty label sequence (a single bare word, e.g. a TLD-only query like `com`), which is consistent with the endpoint being scoped to domain lookups rather than general WHOIS queries.
4. **Invoking `whois` by absolute path (`/usr/bin/whois`)** removes the possibility that a writable/prepended `PATH` entry substitutes a different binary for the intended one. Assumption: the target deployment is a Linux/Debian-family host where the `whois` package installs to `/usr/bin/whois` (the standard location); if the service runs on a different OS or install layout, this constant needs to match the actual binary location.

The sink's contract is preserved: it still returns WHOIS text on `stdout` to the caller via `res.type('text/plain').send(stdout)`, still responds `500` with the same message on any `error` (a missing/renamed binary, a non-existent TLD, or whois's own exit-nonzero behaviour), and produces no output the original didn't already produce - `stderr` remains unused, as before.

**Check performed:** `node --check` on the fixed file in isolation - passed with no syntax errors. `execFile`, `child_process`, and all string/regex methods used are Node.js core APIs already reachable in this file's runtime; no new package was introduced. The domain-validation regex was exercised against representative inputs (`example.com`, `sub.example.co.uk`, `xn--80ak6aa92e.com`, `8.8.8.8` accepted; `-h evil.com`, `; rm -rf /`, `example.com; ls`, `--version`, and an over-length 64-character label rejected) to confirm it accepts well-formed domains and rejects both malformed input and shell/flag-injection payloads.

## Behaviour changes

- Requests where `domain` is not a syntactically valid dotted domain name (including a bare single-label value such as a TLD name, an IP address is still accepted, or any value containing shell metacharacters or spaces) now receive `400 domain query parameter is not a valid domain name` instead of being passed to `whois`. Any input that was a legitimate domain name before is still accepted.
- The `whois` binary is now invoked at the fixed path `/usr/bin/whois` instead of being resolved via `PATH`; if the deployment environment installs `whois` at a different location, the lookup will fail with `500 whois lookup failed` where it previously would have succeeded.
- No change to the success response body/content-type, nor to the `400`/`500` status codes and messages for the cases that already produced them.
