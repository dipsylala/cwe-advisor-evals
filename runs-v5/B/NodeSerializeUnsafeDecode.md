## Verdict

exploitable (confidence: high)

- **cwe_id**: CWE-502 (Deserialization of Untrusted Data)
- **location**: `NodeSerializeUnsafeDecode.js:18`, function `parseProfileCookie`
- **assumptions**: none - the source, sink, and lack of any intervening check are all visible in the single file provided.

## Source

`req.headers.cookie`, the raw HTTP `Cookie` header, which is fully attacker-controlled. The middleware extracts the `profile=` cookie value with a regex (line 8), URL-decodes it with `decodeURIComponent` (line 15), and passes the result straight to the sink with no validation, allowlisting, or integrity check in between.

## Fix

**Library recommendation**: Remove the `node-serialize` dependency entirely - it has no safe version, since `unserialize()` is unsafe by design (it executes any embedded IIFE-style function payload, e.g. `_$$ND_FUNC$$_function(){...}()`). Replace it with the built-in `JSON.parse`, which needs no dependency.

Vulnerable code:

```js
const serialize = require('node-serialize');
...
const decoded = decodeURIComponent(encoded);

// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
req.profile = serialize.unserialize(decoded);
```

Fixed code:

```js
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
  req.profile = (profile !== null && typeof profile === 'object') ? profile : {};

  next();
}

app.get('/account', parseProfileCookie, (req, res) => {
  res.json({ profile: req.profile });
});

module.exports = app;
```

## Explanation

The `node-serialize` sink is removed and replaced with `JSON.parse`, per the CWE-502 JavaScript guidance's primary defence. `node-serialize.unserialize()` detects specially-formatted function markers in its input and evaluates them, so an attacker who controls the `profile` cookie can embed an IIFE that executes arbitrary code in the Node process the moment the cookie is parsed. `JSON.parse` has no equivalent capability - it only ever produces plain data (objects, arrays, strings, numbers, booleans, null), so the same attacker-controlled cookie can no longer reach code execution. The parsed result is also type-checked to be a non-null object before being assigned to `req.profile`, matching the shape the rest of the module already expects (the no-cookie branch defaults to `{}`). Because `req.profile` here is only read back out via `res.json()` and never merged into another object with `Object.assign`, a deep-merge, or bracket-notation writes, there is no downstream prototype-pollution path (CWE-1321) to guard against in this file; that risk applies only if a caller later merges this value into a longer-lived object, per the guidance's note that `JSON.parse` output is safe from code execution but still live, attacker-shaped data.

## Behaviour changes

- **Cookie payload format changes from node-serialize's format to JSON.** Any legitimate client currently setting the `profile` cookie using `node-serialize`'s serialization format must switch to emitting a JSON-encoded object instead. This is unavoidable - the vulnerable format is the vulnerability - but is a wire-format break for existing clients.
- **Malformed input no longer throws.** The original `serialize.unserialize(decoded)` had no surrounding try/catch; an invalid payload would throw and (absent an Express error handler) surface as an unhandled exception / 500 response. The fixed code catches a `JSON.parse` failure and falls back to `req.profile = {}`, so a malformed cookie now degrades to an empty profile instead of erroring. This is a stricter, safer default that matches the existing "no cookie present" branch, but is a visible behaviour change for any code or test that relied on the unserialize failure being thrown.
- **Non-object JSON values are also normalized to `{}`.** If the cookie decodes to valid JSON that isn't an object (e.g. a bare number, string, or array), the original `unserialize` would have returned whatever `node-serialize` reconstructed; the fix coerces any non-object result to `{}` so `req.profile` always has the object shape the route handler expects. This is a defensive addition beyond the minimum needed to close the code-execution weakness, included because `res.json({ profile: req.profile })` and any future consumer of `req.profile` implicitly assume an object.
