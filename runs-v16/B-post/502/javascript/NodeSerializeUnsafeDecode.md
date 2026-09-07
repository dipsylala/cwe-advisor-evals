## Verdict

Exploitable. The `node-serialize.unserialize()` function at line 18 deserializes attacker-controlled data from the HTTP cookie header without validation, allowing arbitrary code execution. An attacker can craft a malicious serialized payload containing an IIFE (Immediately Invoked Function Expression) that executes when deserialized.

## Source

**Location**: `evals/cases/502/javascript/NodeSerializeUnsafeDecode/NodeSerializeUnsafeDecode.js`, line 18

**Source**: `req.headers.cookie` (attacker-controlled HTTP header)
- Line 7: Cookie header extracted from request
- Line 8: Regular expression extracts the `profile=` cookie value
- Line 14: URL-encoded value captured
- Line 15: URL-decoded with `decodeURIComponent()`
- Line 18: **Sink** - decoded value passed to `serialize.unserialize()`, which executes code embedded in the payload

**Sink**: `serialize.unserialize(decoded)` — `node-serialize` library's unserialize method executes JavaScript code during deserialization

## Fix

**Vulnerable code** (line 18):
```javascript
req.profile = serialize.unserialize(decoded);
```

**Fixed code**:
```javascript
const express = require('express');
const Ajv = require('ajv');

const app = express();
const ajv = new Ajv();

// Schema defining allowed profile structure
const profileSchema = {
  type: 'object',
  properties: {
    // Define expected properties; example:
    // userId: { type: 'string' },
    // name: { type: 'string' }
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
    const parsed = JSON.parse(decoded);
    
    // Validate deserialized data against schema
    if (validateProfile(parsed)) {
      req.profile = parsed;
    } else {
      req.profile = {};
    }
  } catch (err) {
    // Invalid JSON or parse error
    req.profile = {};
  }

  next();
}

app.get('/account', parseProfileCookie, (req, res) => {
  res.json({ profile: req.profile });
});

module.exports = app;
```

**Library recommendation**: Remove `node-serialize` dependency. Add `ajv` (>= 8.0.0) for JSON schema validation per `package.json`.

## Explanation

The fix eliminates arbitrary code execution by replacing `node-serialize.unserialize()` — which evaluates JavaScript during deserialization — with `JSON.parse()`, which safely parses JSON without executing code. JSON schema validation via Ajv is then applied to reject any properties not explicitly allowed in the schema, preventing both unexpected object shapes and prototype pollution attempts (`__proto__`, `constructor`, `prototype` keys are rejected by the `additionalProperties: false` schema constraint). Error handling ensures malformed or non-JSON cookies degrade gracefully to an empty profile rather than crashing or executing attacker-supplied code. The combination of safe deserialization format, strict schema validation, and error isolation closes the code execution path.

## Behaviour changes

- **Error handling**: The original code would crash if `serialize.unserialize()` failed or if the payload contained a non-serializable structure. The fixed code catches JSON parse errors and `schema validation` failures, defaulting to an empty profile (`{}`), allowing the request to proceed safely.
- **Cookie content restriction**: The schema validation enforces that only expected profile properties are accepted. Any unexpected properties are rejected, preventing injection of unintended data or prototype pollution keys.
- **Dependency change**: Removes the `node-serialize` library (unsafe) and introduces `ajv` (safe schema validation). The application must define the `profileSchema` properties to match what the legitimate producer sends; an empty schema with `additionalProperties: false` will reject all profiles until schema properties are specified.
- **No return value change**: The caller at line 24 still receives `req.profile` as a plain JavaScript object, preserving the original function signature and response structure.
