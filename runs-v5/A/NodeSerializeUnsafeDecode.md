## Verdict

Confirmed. `serialize.unserialize()` (the `node-serialize` package) is called on a value decoded directly from the `profile` cookie, with no validation in between. `node-serialize`'s `unserialize()` detects any string value that looks like a function definition (values wrapped as `_$$ND_FUNC$$_function(){...}()`) and runs it through `eval()` during deserialization. Because the cookie is fully attacker-controlled, an attacker can set `profile` to a payload such as `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('...')}()"}` (URI-encoded) and achieve arbitrary code execution on the server for every request to `/account`.

## Source

`req.headers.cookie` (the `profile` cookie value), read in `parseProfileCookie` at line 7-8, URI-decoded at line 15, then flows unchanged into the sink.

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

  let profile;
  try {
    profile = JSON.parse(decoded);
  } catch (err) {
    req.profile = {};
    return next();
  }

  if (profile === null || typeof profile !== 'object' || Array.isArray(profile)) {
    req.profile = {};
    return next();
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

`node-serialize` is not a safe substitute for JSON: its `unserialize()` recognizes a special string marker for function values and reconstructs them by calling `eval()` on the embedded source, so any data reaching it is effectively handed code-execution privileges rather than just being parsed into plain objects. There is no configuration flag on the library that disables this behavior, and no sanitization step can reliably neutralize the marker syntax while still supporting legitimate use of the format, so the correct remediation is to stop using the library for attacker-influenced input rather than to try to filter its input.

The fix replaces `serialize.unserialize(decoded)` with `JSON.parse(decoded)`, which has no code-execution path in its grammar - it can only ever produce plain data (objects, arrays, strings, numbers, booleans, null). A `try/catch` handles malformed JSON without crashing the request pipeline, and the added type check ensures `req.profile` is always a plain object (never an array, string, or other primitive) before it is used downstream, matching the shape the rest of the application expects from the cookie. This preserves the original behavior for well-formed profile cookies while eliminating the deserialization-triggered code execution entirely.
