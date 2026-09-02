## Verdict

exploitable (confidence: high)

CWE-78 - Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection'). The `/whois` handler passes an attacker-controlled query parameter straight into a shell command string with no validation, sanitization, or encoding between source and sink.

## Source

`req.query.domain` - the `domain` query-string parameter on `GET /whois`, fully attacker-controlled. The only check applied before use is a truthiness check (`if (!domain)`), which rejects an absent or empty value but does not constrain its contents in any way.

## Fix

Vulnerable code (`WhoisLookupChildProcess.js`, line 15):

```javascript
const express = require('express');
const { exec } = require('child_process');

const app = express();

app.get('/whois', (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).send('domain query parameter is required');
  }

  // VULNERABLE: domain is concatenated into a shell command string unescaped
  exec(`whois ${domain}`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send('whois lookup failed');
    }
    res.type('text/plain').send(stdout);
  });
});

app.listen(3000);

module.exports = app;
```

Fixed code:

```javascript
const express = require('express');
const net = require('net');

const app = express();

const DOMAIN_PATTERN = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$/;
const IANA_WHOIS_SERVER = 'whois.iana.org';
const WHOIS_PORT = 43;

function queryWhois(server, query) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(WHOIS_PORT, server);
    let response = '';
    socket.setEncoding('utf8');
    socket.on('connect', () => {
      socket.write(`${query}\r\n`);
    });
    socket.on('data', (chunk) => {
      response += chunk;
    });
    socket.on('end', () => resolve(response));
    socket.on('error', reject);
  });
}

function extractReferral(response) {
  const match = response.match(/^\s*(?:refer|whois):\s*(\S+)\s*$/im);
  return match ? match[1] : null;
}

app.get('/whois', async (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).send('domain query parameter is required');
  }

  if (!DOMAIN_PATTERN.test(domain)) {
    return res.status(400).send('domain query parameter is invalid');
  }

  try {
    let result = await queryWhois(IANA_WHOIS_SERVER, domain);
    const referral = extractReferral(result);
    if (referral) {
      result = await queryWhois(referral, domain);
    }
    res.type('text/plain').send(result);
  } catch (err) {
    res.status(500).send('whois lookup failed');
  }
});

app.listen(3000);

module.exports = app;
```

## Explanation

The fix removes `child_process.exec()` entirely and replaces it with the WHOIS protocol implemented directly over `net.Socket`, per the language guidance's directive to eliminate command execution where it is incidental to the feature (WHOIS lookups are a plain-text TCP protocol on port 43, not something that requires shelling out). This closes the injection at the root: there is no shell to inject into, since `domain` is written as a line of protocol text over a raw socket rather than interpolated into a string handed to `/bin/sh` or `cmd.exe`. A strict allowlist regex (`DOMAIN_PATTERN`) is added as the secondary defence layer the guidance calls for, restricting the value to valid hostname-label characters and structure before it is used anywhere - this also closes off WHOIS protocol-line injection (e.g. embedded `\r\n` sequences), since the value is now sent as a literal line to the server rather than passed through a shell that would have stripped or errored on such characters differently. The standard WHOIS client behaviour of following a single referral (the IANA root server returns a `refer:`/`whois:` pointer to the authoritative registry for most TLDs) is reproduced with a second `queryWhois()` call so the response returned to the caller matches what the original system `whois` binary would have produced, rather than silently truncating to the root server's summary record.

## Behaviour changes

- Domain format is now validated against a strict hostname allowlist before use; a `domain` value that does not match now gets `400 domain query parameter is invalid` instead of being passed through unchecked. Reason: secondary defence layer required by the guidance, and this is also what prevents WHOIS protocol-line injection now that the value reaches a raw socket write.
- The lookup is now two native TCP queries (IANA root server, then one referral hop if the response names one) instead of a single system `whois` process invocation. Reason: required to preserve the original's returned data - a single unreferred query to the IANA root server typically returns only a referral pointer, not the full registration record, so querying only once would have narrowed the original output. Assumption, stated for reviewer awareness: this follows one referral hop, matching the common case for gTLD lookups; a small number of thin-registry TLDs that require a second referral hop will return a less complete record than the system `whois` client, which follows referrals until exhausted. If full parity is required for those TLDs, extend `queryWhois`/`extractReferral` to loop until no further referral is found.
- Error handling, response content-type (`text/plain`), and the generic `500 whois lookup failed` message on failure are unchanged from the original - no additional error detail is surfaced to the caller.
