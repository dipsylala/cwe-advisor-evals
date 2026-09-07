## Verdict

Exploitable. The `node-serialize.unserialize()` call on line 18 deserializes untrusted cookie data without validation. The `node-serialize` library uses eval-like code execution to reconstruct objects, allowing attackers to run arbitrary code by crafting malicious serialized payloads in the cookie.

## Source

Attacker-controlled HTTP request header `req.headers.cookie`. The application extracts the `profile` parameter value, URL-decodes it, and passes it directly to an unsafe deserialization function without integrity checks or type validation.

## Fix

**Vulnerable code:**
```javascript
const serialize = require('node-serialize');

function parseProfileCookie(req, res, next) {
  const cookieHeader = req.headers.cookie || '';
  const match = cookieHeader.match(/profile=([^;]+)/);
  if (!match) {
    req.profile = {};
    return next();
  }

  const encoded = match[1];
  const decoded = decodeURIComponent(encoded);

  // VULNERABLE: node-serialize.unserialize() executes arbitrary code
  req.profile = serialize.unserialize(decoded);

  next();
}
```

**Fixed code:**
```javascript
const express = require('express');
const Ajv = require('ajv');

const app = express();
const ajv = new Ajv();

// Define schema for profile object - restrict to expected properties
const profileSchema = {
  type: 'object',
  properties: {
    name: { type: 'string' },
    email: { type: 'string' },
    settings: { type: 'object' }
  },
  additionalProperties: false
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
    // Safe: JSON.parse() does not execute code
    const parsed = JSON.parse(decoded);
    
    // Validate against strict schema before use
    if (!validateProfile(parsed)) {
      req.profile = {};
      return next();
    }
    
    req.profile = parsed;
  } catch (err) {
    // Invalid JSON or validation error - default to empty profile
    req.profile = {};
  }

  next();
}

module.exports = app;
```

**Library recommendation:**
Remove `node-serialize` (entirely unsafe; no fixed version exists - the library's core design uses eval-like deserialization). Replace with:
- `JSON.parse()` for deserialization (built-in, safe)
- `ajv` for schema validation (commonly maintained package; confirm current version against SCA tooling)

Update `package.json` to remove `node-serialize` and add `ajv`.

## Explanation

The fix eliminates code execution by replacing `node-serialize.unserialize()` with `JSON.parse()`, which parses JSON data without evaluating any code. Schema validation using Ajv enforces that only expected object properties are deserialized and rejects malicious payloads with unexpected fields or types. The try-catch block handles malformed JSON gracefully by defaulting to an empty profile rather than crashing. This approach prevents object instantiation of arbitrary classes (which is how `node-serialize` achieved code execution) and restricts the deserialized data to a known safe structure before it is used.

This is a **breaking change**: clients must now send JSON-serialized profile data instead of `node-serialize` format. Existing cookies will be rejected and replaced with empty profiles; the server should issue new cookies in the JSON format immediately after fix deployment, or provide a migration period where both formats are accepted.

## Behaviour changes

- **Data format change (breaking):** Consumers must switch from `node-serialize` serialization to JSON. Existing cookies are rejected; clients receive empty profile on parse failure instead of a deserialized object.
- **New dependency:** `ajv` added for schema validation; must be included in `package.json`.
- **Error handling:** Invalid JSON or validation failures now silently default to an empty profile with `req.profile = {}` instead of potentially throwing or executing unsafe code. This is safer but changes the error contract - the handler no longer surfaces parse errors to the caller.
- **Property allowlist:** Only properties defined in `profileSchema` are accepted. Additional properties (e.g., `__proto__`, `constructor`, `prototype`) are explicitly rejected by `additionalProperties: false`, preventing prototype pollution attacks that could occur if untrusted keys were merged into existing objects.
