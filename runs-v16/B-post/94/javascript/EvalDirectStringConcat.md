## Verdict
Exploitable

## Source
`req.body.expression` (line 6) - untrusted HTTP POST body parameter

## Sink
`eval('(' + expression + ')')` (line 15) - executes arbitrary JavaScript code

## Fix

**Vulnerable Code (line 15):**
```javascript
const result = eval('(' + expression + ')');
```

**Fixed Code:**
```javascript
const { Parser } = require('expr-eval');
const parser = new Parser();
const result = parser.evaluate(expression);
```

## Explanation

The `eval()` function executes arbitrary JavaScript code derived from the untrusted `expression` parameter, allowing code injection attacks. An attacker can send expressions like `require('child_process').execSync('whoami')` to execute arbitrary commands. The fix replaces `eval()` with `expr-eval`, a dedicated expression evaluator library designed specifically for safe mathematical and logical expression evaluation. This library parses the input, restricts evaluation to allowed operators and functions, and prevents access to dangerous language features like `require()`, `process`, constructors, and method invocation. For valid mathematical expressions like `"12 * (3 + 4)"`, the fixed code produces identical results while blocking code injection attempts.

## Behaviour changes

**Added dependency:** Requires `expr-eval` npm package as a new dependency - add to `package.json`.

**Rejected inputs:** The fixed code rejects expressions containing code that extends beyond mathematical operations (e.g., `require()`, property access beyond array/object indexing for simple data, function calls outside a whitelist). This is a security feature, not a regression.

**Error messages:** Invalid mathematical syntax throws `SyntaxError` with a message from `expr-eval` parser, replacing the original `eval()` syntax errors. Both halt execution appropriately.

**Return value:** For valid mathematical expressions, the return type and value are identical to the original `eval()`. The HTTP response remains valid.
