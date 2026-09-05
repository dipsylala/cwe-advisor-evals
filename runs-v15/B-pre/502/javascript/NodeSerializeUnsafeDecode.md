## Verdict

Exploitable. The application deserializes untrusted cookie data using `node-serialize.unserialize()`, which executes embedded functions and allows remote code execution.

## Source

Attacker-controlled HTTP request header `Cookie` containing a `profile=` parameter. The header value is extracted via regex (line 8), URL-decoded (line 15), and passed directly to `serialize.unserialize()` without validation.

## Fix

Replace `node-serialize` deserialization with `JSON.parse()` and add strict schema validation:

```javascript
const express = require('express');
const Joi = require('joi');

const app = express();

// Define schema for expected profile structure
const profileSchema = Joi.object({
  username: Joi.string().alphanum().max(30),
  email: Joi.string().email(),
  // Add only expected fields; additionalProperties rejected by default
}).unknown(false);

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
    // Parse JSON instead of using node-serialize
    const parsed = JSON.parse(decoded);
    
    // Validate against schema - rejects unexpected properties
    const { error, value } = profileSchema.validate(parsed);
    if (error) {
      // Reject malformed or unexpected data
      req.profile = {};
      return next();
    }
    
    req.profile = value;
  } catch (e) {
    // Handle JSON parse errors
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

`node-serialize.unserialize()` executes embedded functions during deserialization, enabling remote code execution when parsing attacker-controlled data. The fix replaces it with `JSON.parse()`, which safely parses data as inert JSON structures without executing code. 

Schema validation via Joi enforces that only expected fields are present and rejects any payload attempting to add unexpected properties or prototype-pollution keys. The `unknown(false)` setting makes Joi explicitly reject additional properties. Error handling returns a safe empty profile on malformed input, failing closed.

The cookie format changes from `node-serialize` format to JSON—this is a breaking change, but acceptable because the server controls cookie creation and can emit the new format.

## Behaviour changes

- Cookies with `node-serialize` format no longer deserialize; clients must receive new JSON-formatted cookies from the server.
- Malformed JSON or payloads with unexpected fields result in an empty profile (`{}`) rather than an error, allowing graceful degradation.
- Schema validation restricts profile object to defined fields only, rejecting any attempt to inject additional properties.
- No code execution is possible from cookie data.
