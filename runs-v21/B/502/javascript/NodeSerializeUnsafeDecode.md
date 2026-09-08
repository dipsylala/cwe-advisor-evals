## Verdict

exploitable

## Source

`req.headers.cookie` (HTTP cookie header, attacker-controlled).

Data flow: Cookie header → regex match extraction → URL decode → deserialization sink.

## Fix

### File: NodeSerializeUnsafeDecode.js

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
    const parsed = JSON.parse(decoded);

    // Ensure parsed value is an object and reject prototype pollution keys
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
      if ('__proto__' in parsed || 'constructor' in parsed || 'prototype' in parsed) {
        req.profile = {};
        return next();
      }
      req.profile = parsed;
    } else {
      req.profile = {};
    }
  } catch (e) {
    // Invalid JSON
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

The original code deserializes untrusted cookie data using `node-serialize.unserialize()`, which parses and executes embedded code within the serialized payload, allowing arbitrary code execution. The fix replaces the unsafe deserialization library with `JSON.parse()`, which safely parses JSON without executing any code. The fixed code adds try-catch error handling to gracefully handle malformed JSON by assigning an empty object when parsing fails. Additional validation rejects arrays and non-object values, and specifically filters out prototype pollution keys (`__proto__`, `constructor`, `prototype`) that could otherwise mutate `Object.prototype` during property assignment, preventing CWE-1321.

## Behaviour changes

The deserialization format changes from node-serialize binary format to JSON format. This is a breaking change: any existing cookies set by this application in node-serialize format will fail to parse and result in an empty profile object; such cookies must be invalidated or migrated. The application now rejects array values and non-object values (previously node-serialize could instantiate various types); requests with these values receive an empty profile object instead. The application rejects any object containing prototype pollution keys (`__proto__`, `constructor`, `prototype`) by treating such requests as invalid input, which is a security hardening and does not represent loss of legitimate functionality. Error handling is improved: invalid JSON is caught and handled gracefully instead of crashing the application.
