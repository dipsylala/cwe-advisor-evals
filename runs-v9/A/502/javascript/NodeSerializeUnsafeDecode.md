## Verdict

Confirmed. `parseProfileCookie` takes the `profile` cookie straight from the request, URL-decodes it, and hands it to `node-serialize`'s `unserialize()`. `node-serialize` supports reviving functions: a payload whose value is a string of the form `_$$ND_FUNC$$_function(){...}()` is turned back into an executed JavaScript function during unserialize. Because the cookie is fully attacker-controlled and reaches this sink with no validation, an attacker can set a `profile` cookie that runs arbitrary code on every request that hits `/account` (or any other route behind this middleware) — remote code execution, not just object-shape confusion.

## Source

`req.headers.cookie` (line 7) — the raw `Cookie` request header, attacker-controlled — narrowed by regex to the `profile=` value (line 8) and URL-decoded (line 15). This flows unmodified into the sink at line 18.

## Fix

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
    const profile = JSON.parse(decoded);
    if (profile === null || typeof profile !== 'object' || Array.isArray(profile)) {
      req.profile = {};
      return next();
    }
    req.profile = profile;
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

The `node-serialize` package's `unserialize()` is not a safe substitute for `JSON.parse()`: it recognizes a special string marker (`_$$ND_FUNC$$_`) inside serialized object values and, when present, `eval`s the trailing text as a function and invokes it while reconstructing the object. Since the input here is a browser-supplied cookie, any visitor can set `profile=<uri-encoded payload>` containing that marker plus a self-invoking function body and get it executed server-side on every request through this middleware — a textbook unsafe-deserialization-to-RCE chain.

The fix removes `node-serialize` from the request path entirely and replaces it with `JSON.parse()`, which only ever produces plain data (objects, arrays, strings, numbers, booleans, null) and has no facility for reviving executable code. The parse is wrapped in `try/catch` because cookie content is unreliable and previously-malformed or tampered values should degrade to an empty profile rather than throw an unhandled exception into the request pipeline. An additional shape check rejects non-object results (e.g. a bare number or array smuggled into the cookie) so `req.profile` is always a plain object, matching what the rest of the application expects.

If the profile data must ever come back to the server having been set by the server itself (e.g. a signed session), prefer a signed/encrypted cookie (such as `cookie-signature` or Express's own `cookie-parser` signed-cookie support) so tampering is detected before the value is trusted at all — `JSON.parse` alone stops code execution but does not stop a client from forging arbitrary profile field values.
