## Verdict

Exploitable. The untrusted `domain` query parameter is directly interpolated into a shell command string passed to `child_process.exec()` with no validation. An attacker can inject shell metacharacters to execute arbitrary commands on the host.

## Source

`req.query.domain` (line 8) - HTTP query parameter, attacker-controlled

## Fix

**Vulnerable Code (line 15):**
```javascript
exec(`whois ${domain}`, (error, stdout, stderr) => {
```

**Fixed Code:**
```javascript
const express = require('express');
const net = require('net');

const app = express();

// Looks up WHOIS registration details for a domain the caller wants to check.
app.get('/whois', (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).send('domain query parameter is required');
  }

  // Use net module to make a direct WHOIS query instead of shell exec
  const socket = net.createConnection({ host: 'whois.iana.org', port: 43 });
  let responseData = '';
  let responseSent = false;

  socket.on('connect', () => {
    socket.write(`${domain}\r\n`);
  });

  socket.on('data', (data) => {
    responseData += data.toString();
  });

  socket.on('end', () => {
    if (!responseSent) {
      responseSent = true;
      res.type('text/plain').send(responseData);
    }
  });

  socket.on('error', (error) => {
    if (!responseSent) {
      responseSent = true;
      res.status(500).send('whois lookup failed');
    }
  });

  // Set timeout to prevent hanging connections
  socket.setTimeout(5000, () => {
    socket.destroy();
    if (!responseSent) {
      responseSent = true;
      res.status(500).send('whois lookup failed');
    }
  });
});

app.listen(3000);

module.exports = app;
```

## Explanation

The fix eliminates the shell command execution by replacing `child_process.exec()` with a direct TCP connection using Node.js's `net` module (standard library). The WHOIS protocol is a simple text protocol over TCP port 43. Instead of invoking a shell and passing the domain through string interpolation, the code now opens a socket connection to the WHOIS server and writes the domain directly to it. The domain is no longer interpolated into a command string, so shell metacharacters cannot be used to inject commands. The socket receives the WHOIS server's response and sends it to the client in the same format as the original code. Error handling is preserved: both connection failures and timeouts result in the same 500 status response. The `responseSent` flag prevents multiple responses being sent if error and end events both fire.

## Behaviour changes

- The WHOIS lookup now uses a direct TCP connection to `whois.iana.org` port 43 instead of invoking the local `whois` command-line tool. This eliminates shell invocation entirely.
- A 5-second timeout is added to prevent connections from hanging indefinitely.
- The response structure is identical (plain text WHOIS data sent to the client).
- Error handling is identical (generic 500 status message on failure; the original code also discarded stderr).
- Performance may improve slightly due to reduced subprocess overhead; latency depends on network connectivity to the WHOIS server.
