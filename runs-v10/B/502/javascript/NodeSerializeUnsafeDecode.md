## Verdict

Confirmed. Line 18 passes untrusted cookie data directly to `serialize.unserialize()`, which executes embedded code in the serialized payload, allowing arbitrary code execution (CWE-502).

## Source

```javascript
const encoded = match[1];
const decoded = decodeURIComponent(encoded);

// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
req.profile = serialize.unserialize(decoded);  // Line 18
```

The cookie value flows from `req.headers.cookie` (untrusted HTTP header) → regex extraction → URL decoding → directly into `node-serialize.unserialize()`, which can instantiate arbitrary objects and execute embedded code.

## Fix

```javascript
const express = require('express');
const Ajv = require('ajv');

const app = express();
const ajv = new Ajv();

// Define strict schema for profile object - only allow expected properties
const profileSchema = {
  type: 'object',
  properties: {
    userId: { type: 'string' },
    username: { type: 'string' },
    email: { type: 'string' },
    role: { type: 'string' }
  },
  additionalProperties: false,
  required: []
};

const validateProfile = ajv.compile(profileSchema);

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
    // Parse with JSON.parse instead of node-serialize
    const parsed = JSON.parse(decoded);
    
    // Validate against strict schema before use
    if (!validateProfile(parsed)) {
      req.profile = {};
      return next();
    }
    
    req.profile = parsed;
  } catch (error) {
    // Invalid JSON or validation error - reject the cookie
    req.profile = {};
  }

  next();
}

app.get('/account', parseProfileCookie, (req, res) => {
  res.json({ profile: req.profile });
});

module.exports = app;
```

**Dependency change:** Remove `node-serialize` and add `ajv` to `package.json` dependencies for schema validation.

## Explanation

The fix replaces `node-serialize.unserialize()` with `JSON.parse()`, which safely parses JSON without executing embedded code. The deserialized object is then validated against a strict JSON schema using Ajv, which enforces `additionalProperties: false` and an explicit property whitelist. This ensures only expected fields can be present in the profile object and rejects any attempt to inject prototype pollution keys or unexpected properties. If validation fails or JSON parsing throws (malformed input), the profile defaults to an empty object, safely rejecting the untrusted cookie.

## Behaviour changes

- **Deserialization format**: Changed from `node-serialize` binary format to JSON (request format must change to match)
- **Failure mode**: Malformed or non-JSON cookie values now silently default `req.profile` to `{}` instead of throwing
- **Type enforcement**: Only whitelisted properties (`userId`, `username`, `email`, `role`) are accepted; any other property is rejected
- **Code execution**: Eliminated; arbitrary code in serialized data can no longer be executed
