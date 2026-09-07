## Verdict

**VULNERABLE**: The code at line 18 calls `serialize.unserialize()` on untrusted cookie data without validation. The `node-serialize` library's `unserialize()` method executes embedded code, allowing remote code execution. This is confirmed as CWE-502 (Deserialization of Untrusted Data).

## Source

Attacker-controlled HTTP `Cookie` header (`req.headers.cookie`). The profile value is extracted via regex match at line 8, URL-decoded at line 15, and passed untrusted to the vulnerable sink.

## Fix

Replace `node-serialize.unserialize()` with `JSON.parse()` and add error handling with basic validation. This eliminates code execution while preserving the data-handling contract.

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

  try {
    // Use JSON.parse instead of serialize.unserialize to prevent code execution
    const parsed = JSON.parse(decoded);
    
    // Validate that parsed value is an object
    if (parsed && typeof parsed === 'object') {
      req.profile = parsed;
    } else {
      req.profile = {};
    }
  } catch (err) {
    // If JSON parsing fails, treat as invalid
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

The original code used `node-serialize.unserialize()`, which evaluates embedded IIFE (Immediately Invoked Function Expressions) within the serialized data. An attacker can craft a malicious cookie payload containing arbitrary JavaScript that executes during deserialization.

The fix replaces `serialize.unserialize()` with `JSON.parse()`, which safely parses JSON without code execution. JSON is a data-only format that cannot contain executable code. A try-catch block handles malformed JSON gracefully by defaulting to an empty object. A type check validates that the parsed value is an object before using it, rejecting primitives or unexpected types.

This preserves the existing behavior: parsing the cookie data and assigning it to `req.profile`, while eliminating the remote code execution vector. The removal of the `node-serialize` dependency is a prerequisite for this fix.

## Behaviour changes

- **Before**: Malicious cookie payloads containing JavaScript code would execute during deserialization.
- **After**: Only valid JSON objects are accepted; invalid JSON is silently ignored and treated as an empty profile. Non-object JSON values (primitives, arrays) are rejected and default to an empty object. Code execution is impossible.
- **Data format change**: Cookies must now contain JSON instead of node-serialize format. This is a breaking change for clients sending node-serialize formatted cookies; they must be updated to send valid JSON. Client-side cookie generation should use `JSON.stringify()` instead of `serialize()`.
