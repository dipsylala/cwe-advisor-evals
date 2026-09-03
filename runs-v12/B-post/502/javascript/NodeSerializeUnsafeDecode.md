## Verdict

Exploitable. Untrusted user data from HTTP cookie headers flows directly to `serialize.unserialize()` without validation, allowing arbitrary code execution.

## Source

User-supplied HTTP `Cookie` header, extracted via regex match at line 8 and URL-decoded at line 15.

## Fix

**Vulnerable code (lines 17-18):**
```javascript
  // SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
  req.profile = serialize.unserialize(decoded);
```

**Fixed code:**
```javascript
const express = require('express');
const Joi = require('joi');

const app = express();

// Define schema for expected profile structure
const profileSchema = Joi.object({
  userId: Joi.string(),
  username: Joi.string(),
  email: Joi.string().email()
}).unknown(false); // Reject unexpected properties

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
    // Use JSON.parse() instead of serialize.unserialize()
    const profile = JSON.parse(decoded);
    
    // Validate deserialized data against schema
    const { error, value } = profileSchema.validate(profile);
    if (error) {
      req.profile = {};
      return next();
    }
    
    req.profile = value;
  } catch (e) {
    // Handle malformed JSON
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

The fix eliminates code execution by replacing the `node-serialize` library's unsafe `unserialize()` method (which evaluates embedded functions during deserialization) with `JSON.parse()`, which parses the data as an inert data structure only. Schema validation using Joi enforces that only expected properties with correct types are accepted; the `unknown(false)` setting rejects unexpected properties, preventing prototype pollution attacks. Try-catch error handling gracefully degrades to an empty profile object if the cookie contains malformed JSON, maintaining application stability while preventing exploitation.

## Behaviour changes

- **Error handling**: Malformed JSON now silently fails with empty profile instead of throwing. Caller still receives valid response (profile defaults to `{}`).
- **Library dependency**: Removes dependency on `node-serialize`; adds `joi` for schema validation. Both are npm package changes, not runtime behavioural changes.
- **Data format**: Application now expects JSON-serialized profile in cookie, not `node-serialize` binary format. This is a breaking change for existing cookies; clients must re-authenticate or cookies must be regenerated with JSON encoding.
- **Type validation**: Deserialized object properties are now strictly validated against schema; unexpected fields are rejected rather than silently accepted.
