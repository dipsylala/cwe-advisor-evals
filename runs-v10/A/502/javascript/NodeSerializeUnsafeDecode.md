## Verdict
CONFIRMED. Line 18 deserializes untrusted cookie data using `serialize.unserialize()`, which executes arbitrary code in `node-serialize`.

## Source
Cookie header (`req.headers.cookie`) is extracted at line 7-8, URL-decoded at line 15, and passed directly to `serialize.unserialize()` at line 18 without validation.

## Fix
Replace `node-serialize` with `JSON.parse()` for safe deserialization:

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
The `node-serialize` library's `unserialize()` method evaluates function expressions during deserialization, enabling remote code execution. `JSON.parse()` safely parses structured data without code execution. The try-catch handles malformed JSON gracefully by setting an empty profile, matching the behavior when no cookie is present.
