## Verdict

Unsafe deserialization of untrusted cookie data using `node-serialize.unserialize()` creates a remote code execution vulnerability. The `node-serialize` library can reconstruct arbitrary objects, allowing an attacker to craft malicious payloads that execute code during deserialization.

## Source

Line 18 in `parseProfileCookie()`:
```javascript
req.profile = serialize.unserialize(decoded);
```

The cookie value is extracted from user-supplied headers and deserialized without validation using a library known for code execution vulnerabilities.

## Fix

Replace `node-serialize.unserialize()` with `JSON.parse()`:

```javascript
const express = require('express');

const app = express();

function parseProfileCookie(req, res, next) {
  const cookieHeader = req.headers.cookie || '';
  const match = cookieHeader.match(/profile=([^;]+)/);
  if (!match) {
    req.profile = {};
    return next();
  }

  const encoded = match[1];
  const decoded = decodeURIComponent(encoded);

  try {
    req.profile = JSON.parse(decoded);
  } catch (err) {
    req.profile = {};
  }

  next();
}

app.get('/account', parseProfileCookie, (req, res) => {
  res.json({ profile: req.profile });
});

module.exports = app;
```

## Explanation

CWE-502 occurs when untrusted data is deserialized by libraries that permit arbitrary object reconstruction. The `node-serialize` library is particularly dangerous because it can instantiate arbitrary classes and invoke their constructors, which can be exploited for remote code execution.

JSON is a language-neutral, format-preserving alternative that treats data as data only—it does not instantiate classes or execute code during parsing. Replacing `serialize.unserialize()` with `JSON.parse()` eliminates the RCE vector while maintaining the ability to store and retrieve profile structures.

The try-catch block handles malformed JSON gracefully by falling back to an empty profile object, ensuring the application continues to function if the cookie is corrupted or from an older format.

If the application must continue using `node-serialize` for backward compatibility, the profile must originate only from the application itself (signed, server-generated cookies) rather than accepting arbitrary user input.
