## Verdict

Exploitable

## Source

`req.headers.cookie` — HTTP cookie header controlled by the attacker

## Fix

**Vulnerable Code (line 18):**
```javascript
req.profile = serialize.unserialize(decoded);
```

**Fixed Code:**
```javascript
const Ajv = require('ajv');
const ajv = new Ajv();

// Define schema with strict type checking and no extra properties
const profileSchema = {
  type: 'object',
  properties: {},
  additionalProperties: false,
  required: []
};

const validateProfile = ajv.compile(profileSchema);

// In the parseProfileCookie function, replace the unserialize call:
try {
  const profile = JSON.parse(decoded);
  if (!validateProfile(profile)) {
    req.profile = {};
  } else {
    req.profile = profile;
  }
} catch (error) {
  req.profile = {};
}
```

## Explanation

The original code uses `node-serialize.unserialize()`, which deserializes untrusted data by executing embedded IIFEs during object reconstruction. This allows arbitrary code execution when the attacker controls the cookie value. The fix replaces this unsafe deserialization with `JSON.parse()`, which treats input as inert data, combined with strict JSON schema validation using Ajv. The schema rejects any properties beyond those explicitly allowed (`additionalProperties: false`), and try-catch error handling safely defaults to an empty object on parse failure or validation failure. The `node-serialize` dependency should be removed from `package.json` entirely.

## Behaviour changes

- **Deserialization format change**: The code now accepts only valid JSON instead of JavaScript object notation with function expressions. If the cookie previously relied on serialized function expressions or other non-JSON constructs, this will break those payloads (intended security hardening, not a regression).
- **Error handling**: Malformed input or validation failures now silently default to an empty profile object instead of throwing an exception. This is safer than crashing the request, and aligns with the existing `if (!match)` branch.
- **Schema definition required**: The `profileSchema` must be updated with the actual expected properties of the profile object (currently empty as a safe default). This property list is a security boundary and should be audited alongside the fix.
- **New dependency**: Ajv (or an alternative schema validator such as Joi or Zod) is required as a new dependency. Ensure it is added to `package.json` with a pinned version verified against SCA/advisory data.

