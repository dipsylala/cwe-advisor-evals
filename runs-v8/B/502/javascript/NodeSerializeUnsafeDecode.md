## Verdict

Exploitable. The attacker controls the cookie value that is passed to `serialize.unserialize()` without validation or integrity checks. The node-serialize library's `unserialize()` function executes embedded code patterns (IIFE), allowing arbitrary code execution.

## Source

`req.headers.cookie` — attacker-controlled HTTP cookie header. The profile parameter is extracted via regex, URL-decoded, and passed directly to deserialization.

Data flow: cookie → regex extraction → URL decode → `serialize.unserialize()` (sink on line 18).

## Fix

**Vulnerable code:**

```javascript
const encoded = match[1];
const decoded = decodeURIComponent(encoded);

// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
req.profile = serialize.unserialize(decoded);
```

**Fixed code:**

```javascript
const encoded = match[1];
const decoded = decodeURIComponent(encoded);

req.profile = {};
try {
  const parsed = JSON.parse(decoded);
  
  // Validate that parsed is an object and only contains expected properties
  if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
    // Whitelist allowed profile properties
    const allowedKeys = ['name', 'email', 'preferences'];
    for (const key of allowedKeys) {
      if (key in parsed) {
        req.profile[key] = parsed[key];
      }
    }
  }
} catch (e) {
  // JSON parsing failed; req.profile remains an empty object
}
```

## Explanation

The fix replaces node-serialize's unsafe `unserialize()` with `JSON.parse()`, which parses the string as data without executing code. A try-catch block handles malformed JSON gracefully. Type validation ensures the parsed value is an object, and a whitelist extracts only expected profile properties into a fresh object, rejecting any additional or prototype-polluting keys (`__proto__`, `constructor`, `prototype`). This prevents both code execution and prototype pollution. The default empty object fallback ensures the middleware always leaves `req.profile` in a safe state.

## Behaviour changes

- **Error handling**: Malformed JSON in the cookie now results in an empty profile object instead of parsing failure or code execution. This is a behaviour change but safe and necessary — an invalid cookie should not crash the middleware.
- **Property filtering**: Only whitelisted keys are copied to `req.profile`. Any attacker-supplied keys not in the allowlist are silently rejected. This is intentional and prevents prototype pollution.
- **Initialization**: `req.profile` is now always initialized, even on parse failure, guaranteeing the downstream handler receives a consistent object shape.
