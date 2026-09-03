## Verdict

Exploitable. Attacker-controlled cookie data flows directly to `serialize.unserialize()`, which executes embedded code (Arbitrary Code Execution).

## Source

HTTP request cookie header (`req.headers.cookie`). The `profile` parameter is extracted via regex (line 8), URL-decoded (line 15), and passed to deserialization without validation or integrity checks.

## Fix

**Vulnerable Code** (lines 17-18):
```javascript
  // SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
  req.profile = serialize.unserialize(decoded);
```

**Fixed Code**:
```javascript
  try {
    const parsed = JSON.parse(decoded);
    
    // Validate against expected schema - only allow known profile properties
    if (typeof parsed !== 'object' || parsed === null) {
      req.profile = {};
    } else {
      const profile = {};
      // Whitelist allowed properties only
      if (typeof parsed.userId === 'string') profile.userId = parsed.userId;
      if (typeof parsed.displayName === 'string') profile.displayName = parsed.displayName;
      if (typeof parsed.email === 'string') profile.email = parsed.email;
      req.profile = profile;
    }
  } catch (err) {
    // Invalid JSON in cookie - treat as missing profile
    req.profile = {};
  }
```

Also remove the unused `serialize` dependency:
```javascript
// Remove this line:
// const serialize = require('node-serialize');
```

## Explanation

The fix replaces `node-serialize.unserialize()` with `JSON.parse()`, eliminating code execution. `unserialize()` evaluates embedded IIFE expressions in the serialized payload; `JSON.parse()` parses only JSON data structures with no code execution.

The fix adds an allowlist-based schema validation that inspects the deserialized object type and copies only expected string properties to a fresh `profile` object. Unexpected properties (including `__proto__`, `constructor`, `prototype`) are rejected. Malformed JSON is caught by the try-catch and treated as a missing profile rather than failing the request.

The removal of the `node-serialize` dependency eliminates the attack surface entirely and reduces dependencies.

## Behaviour changes

**Return value preservation**: Original code assigns any object returned by `unserialize()` directly to `req.profile`. Fixed code assigns a fresh object with only whitelisted properties, which is a type and shape guarantee - `req.profile` is now guaranteed to be a plain object with only string values for `userId`, `displayName`, and `email`, or an empty object on error. Downstream code that expects arbitrary properties from the cookie will no longer receive them.

**Error handling**: Original code does not catch deserialization errors; parsing a malformed cookie value will throw, causing `next()` to never be called and the request to hang. Fixed code catches JSON parse errors and treats them as missing profiles (empty object), allowing the request to proceed. This is safer because malformed cookies (whether attack attempts or legitimate corruption) do not crash the middleware.

**Input validation**: Added explicit schema validation with property-type checking. The original code trusted whatever `unserialize()` produced; the fixed code enforces that only known properties with expected types are accepted.

