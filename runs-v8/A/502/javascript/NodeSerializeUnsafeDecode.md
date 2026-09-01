## Verdict

Confirmed deserialization of untrusted data in user-controlled cookie. Line 18 passes an unsanitized cookie value to `serialize.unserialize()`, which can instantiate arbitrary objects and execute code. Replace unsafe serialization with JSON.

## Source

Line 7-8: Cookie data is extracted from request headers with no validation.

Line 14: The cookie value is extracted via regex group match.

Line 15: Value is URL-decoded but not validated for structure.

Line 18 (sink): `serialize.unserialize(decoded)` deserializes the untrusted string. The `node-serialize` library can instantiate arbitrary constructor functions during deserialization, enabling remote code execution.

## Fix

Replace `node-serialize` with built-in JSON serialization:

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
    req.profile = JSON.parse(decoded);
  } catch (e) {
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

`node-serialize.unserialize()` is fundamentally unsafe for untrusted input because it can instantiate any JavaScript object and call arbitrary constructors. The `node-serialize` documentation itself warns against untrusted input.

`JSON.parse()` is safe because it only constructs plain objects and primitive values—it cannot invoke code or call constructors. Wrapping the parse in a try-catch gracefully handles malformed cookie values by falling back to an empty profile object, maintaining the original function's behavior for invalid input while eliminating code execution risk.

If the client must send data with class instances or methods, the code would require an allow-list validation schema before deserialization—but for cookies storing profile data, JSON is the standard, safe approach.
