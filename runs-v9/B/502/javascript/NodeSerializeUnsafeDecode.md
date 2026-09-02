## Verdict

- **cwe_id**: CWE-502 (Deserialization of Untrusted Data)
- **location**: `NodeSerializeUnsafeDecode.js:18`
- **verdict**: exploitable
- **confidence**: high

## Source

- **source**: `req.headers.cookie` - the raw HTTP `Cookie` request header, fully attacker-controlled and unauthenticated. `parseProfileCookie` extracts the `profile=` segment with a regex (`match[1]`) and URL-decodes it (`decodeURIComponent`) into `decoded`, with no integrity check or allowlist between the header and the sink.
- **sink**: `serialize.unserialize(decoded)` at line 18, from the `node-serialize` package. This function is a documented arbitrary-code-execution sink: it looks for values prefixed `_$$ND_FUNC$$_` and evaluates the remainder as a JavaScript function body via an IIFE, so a crafted `Cookie: profile=` value executes attacker-supplied code in the request handler, with no separate execution flag or opt-out required to reach it.
- **data flow**: `req.headers.cookie` -> regex match -> `decodeURIComponent` -> `serialize.unserialize()` -> `req.profile` -> `res.json({ profile: req.profile })`. Nothing on this path validates, signs, or type-restricts the payload before deserialization, so the path is fully exploitable as reported.

## Fix

**library_recommendation**: Remove the `node-serialize` dependency entirely rather than upgrading it. Per the loaded JavaScript guidance for CWE-502, `node-serialize`'s `unserialize()` is unsafe by design (it evaluates embedded function payloads), not unsafe only in some version range, so there is no minimum safe version to cite - the fix is to stop using the library and deserialize with the built-in `JSON.parse()` instead. Drop the `node-serialize` entry from `package.json`/lockfile as a follow-up; confirm no other module in the codebase still imports it before removing the dependency itself.

**Vulnerable code**:
```js
const express = require('express');
const serialize = require('node-serialize');

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

  // SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
  req.profile = serialize.unserialize(decoded);

  next();
}
```

**Fixed code**:
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

  req.profile = JSON.parse(decoded);

  next();
}
```

## Explanation

The weakness is the choice of deserialization format, not the surrounding cookie-parsing logic, so the fix is a one-line swap: `serialize.unserialize(decoded)` is replaced with `JSON.parse(decoded)`, and the now-unused `node-serialize` import is dropped. `JSON.parse` can only ever produce plain data (objects, arrays, strings, numbers, booleans, null) - it has no mechanism to construct or invoke functions from the input, so the code-execution path that made this exploitable is closed regardless of what an attacker puts in the `profile` cookie value. The rest of the request-handling contract is preserved: the call still returns a value synchronously, that value is still assigned straight to `req.profile`, and a malformed payload still throws synchronously (a `SyntaxError` from `JSON.parse` in place of `node-serialize`'s own parse error), which Express handles identically via its default synchronous-middleware-error path. Because `req.profile` is assigned directly from the parsed value rather than merged into an existing object with `Object.assign`/spread/a deep-merge helper, and the endpoint only reads it back out via `res.json`, the prototype-pollution follow-on noted in the guidance (CWE-1321) does not apply to this snippet as written; it would need to be revisited if `req.profile` is later merged into another object elsewhere in the codebase. Schema validation (Joi/Ajv/Zod) is listed in the guidance as further defense-in-depth for the shape of `profile`, but is not required to close this specific CWE-502 finding and was left out to keep the change scoped to the reported sink.

## Behaviour changes

- Removed the `const serialize = require('node-serialize');` import - it is unused once the sink is replaced. Reason: dead import resulting directly from the fix.
- Legitimate values that previously round-tripped through `node-serialize` because they contained function-typed data (an `_$$ND_FUNC$$_`-prefixed field) will now fail to parse and throw, instead of succeeding. Reason: that capability - constructing executable code from the cookie - is the vulnerability itself; nothing in the visible code path relies on functions being present in `req.profile`, and restoring it would reintroduce the weakness.
- All other behaviour is unchanged: same success-path return shape (a plain object assigned to `req.profile`), same `res.json({ profile: req.profile })` response shape for legitimate JSON-object payloads, and same synchronous-throw-on-malformed-input failure mode (Express's default error handler), so this is effectively `none` beyond the two items above.
