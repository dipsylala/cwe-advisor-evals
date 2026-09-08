## Verdict
CONFIRMED - Unsafe deserialization of untrusted cookie data via `serialize.unserialize()` creates a remote code execution vulnerability.

## Source
The vulnerability originates from the `profile` cookie value (line 8-14), extracted from user-controlled HTTP headers and decoded (line 15), then passed to an unsafe deserialization function.

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

  // Safe: Use JSON.parse instead of serialize.unserialize
  try {
    const parsed = JSON.parse(decoded);
    // Ensure it's an object, not an array or primitive
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      req.profile = parsed;
    } else {
      req.profile = {};
    }
  } catch (err) {
    // Invalid JSON - treat as missing profile
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
The `node-serialize` library's `unserialize()` function deserializes arbitrary JavaScript objects, allowing an attacker to inject malicious serialized code in the cookie that executes during deserialization. This enables remote code execution.

The fix replaces `serialize.unserialize()` with `JSON.parse()`, which only deserializes JSON data without executing code. JSON is inherently safe because it is a pure data format with no executable semantics. Added error handling catches invalid JSON (malformed cookies) and treats them as empty profiles. The type check ensures only objects (not primitives or arrays) are accepted as profile data, preventing edge cases where JSON contains unexpected types.
