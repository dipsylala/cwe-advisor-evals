## Verdict

Exploitable. CWE-502 (Deserialization of Untrusted Data).

## Source

`req.headers.cookie` (attacker-controlled HTTP request header) - the `profile` cookie value is extracted with a regex, URL-decoded, and passed unmodified into the sink with no validation or integrity check in between.

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
    const parsed = JSON.parse(decoded);
    profile = (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) ? parsed : {};
  } catch (err) {
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

`node-serialize`'s `unserialize()` reconstructs any embedded function marker (`_$$ND_FUNC$$_...`) by running it through `eval`, so an attacker who controls the `profile` cookie can execute arbitrary code in the server process merely by having this middleware run - no further sink is needed. `node-serialize` has no safe mode or class allowlist; its deserialization mechanism is inherently eval-based, so the only viable fix is to stop speaking its format and switch the decoder to `JSON.parse()`, which parses data without ever invoking application code. The `require('node-serialize')` import and its call are removed entirely. The parsed result is additionally checked to be a plain object (not `null`, not an array) before being assigned to `req.profile`, since the value flows straight into a JSON response and nothing downstream should have to allow for a stray primitive or array masquerading as a profile object. Because this value is only read (via `res.json`) and never merged into another object with `Object.assign`/spread/a deep-merge helper, the prototype-pollution follow-on that a `JSON.parse` swap can otherwise leave behind (CWE-1321) does not apply to this code path as written; if a later change merges `req.profile` into another object, `__proto__`/`constructor`/`prototype` keys must be rejected at that point.

## Behaviour changes

- **Wire format for the `profile` cookie changes from node-serialize's custom format to plain JSON.** This is a breaking change for whatever sets that cookie (not present in this file) - any producer serializing with `node-serialize.serialize()` must switch to `JSON.stringify()`, or the cookie will simply fail to parse and the request will fall back to an empty profile. This is the necessary consequence of removing the only sink capable of the vulnerability; there is no producer-compatible restricted mode for this library.
- **Malformed/non-JSON cookie no longer throws.** Originally, a cookie that `node-serialize.unserialize()` could not parse would throw synchronously, which Express would forward to its default error handler (500 response). The fix wraps parsing in try/catch and falls back to `req.profile = {}`, matching the existing behaviour for a missing cookie and letting the request continue with a 200 response instead of a 500. This is a deliberate improvement per the language guidance ("add try-catch error handling") rather than an accidental change, but it is a real difference in observable behaviour on malformed input and is called out here for that reason.
- **Non-object JSON values (e.g. `"profile=5"` or `"profile=[1,2]"`) now resolve to `{}` instead of being assigned as-is.** The original `unserialize()` call would have assigned whatever it reconstructed (including a non-object) directly to `req.profile`; the fix normalizes any non-object result to an empty object so `res.json({ profile: req.profile })` always returns an object under `profile`, consistent with the no-cookie branch already in the file.

No other arguments, return values, or control flow were changed. The `serialize` import is removed because the fix's own change made it unused.

## Verification

`node --check` against the fixed file in a scratch location (outside the repo): passed with no syntax errors. No test suite ships with this case file, and no build step applies to a single Express middleware file, so no further automated check was available; the try/catch and object-type guard were traced by hand against each caller (`app.get('/account', parseProfileCookie, ...)` and the `res.json({ profile: req.profile })` handler) to confirm `req.profile` is always defined and always an object when `next()` is called.
