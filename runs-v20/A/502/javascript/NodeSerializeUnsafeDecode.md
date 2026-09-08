## Verdict

Confirmed. `parseProfileCookie` takes the `profile` cookie straight from the request header, URL-decodes it, and passes the result to `node-serialize`'s `unserialize()`. `node-serialize` restores function-valued properties by wrapping their source in an IIFE and running it through `eval()` during unserialization, so a cookie value such as `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('...')}()"}` executes attacker-supplied code the moment this middleware runs, with no authentication required.

## Source

`req.headers.cookie` (the `profile=` cookie value), read in `parseProfileCookie` at `NodeSerializeUnsafeDecode.js:7-15`, flowing into the sink at line 18.

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

  let profile;
  try {
    profile = JSON.parse(decoded);
  } catch (err) {
    profile = {};
  }

  if (profile === null || typeof profile !== 'object' || Array.isArray(profile)) {
    profile = {};
  }

  req.profile = profile;

  next();
}

app.get('/account', parseProfileCookie, (req, res) => {
  res.json({ profile: req.profile });
});

module.exports = app;
```

## Explanation

`node-serialize` is not safe to run over attacker-controlled input: its `unserialize()` looks for a `_$$ND_FUNC$$_` marker in any string property and, when found, evaluates the remainder as JavaScript via `eval()`. That behavior is inherent to how the library restores functions - there is no safe-mode flag or allowed-classes option that disables it, so the only sound remediation is to stop feeding it untrusted data.

The cookie only ever needs to carry a plain data object (the profile shown back in the `/account` response), so the fix swaps the sink for `JSON.parse`, which has no code-execution path: it can only produce strings, numbers, booleans, null, plain objects, and arrays. The `try/catch` treats a malformed or non-JSON cookie the same way the original code already treated a missing cookie (an empty profile) rather than letting an exception surface from the middleware. The added type check rejects a top-level array or primitive JSON value, keeping `req.profile`'s shape consistent with what the rest of the route expects (`res.json({ profile: req.profile })` assumes an object).

If some other part of the application originally set this cookie using `node-serialize`'s `serialize()`, that producer must be moved to `JSON.stringify()` as part of this change so the two sides keep speaking the same format - this file does not include that producer, so there is nothing here to update, but the migration is not complete until every writer of the `profile` cookie is checked.
