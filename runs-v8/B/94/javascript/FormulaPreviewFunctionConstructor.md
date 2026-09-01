## Verdict

Exploitable.

## Source

`req.body.expression` in formulaController.js (line 6), user-controlled input from the HTTP request body passed without validation.

## Fix

**Vulnerable code:**
```javascript
// formulaEngine.js, line 4
const fn = new Function('order', `return (${expression});`);
```

**Fixed code:**
```javascript
// formulaEngine.js
const { Parser } = require('expr-eval');

function evaluateFormula(expression, order) {
  const parser = new Parser();
  const expr = parser.parse(expression);
  return expr.evaluate({ order });
}
```

**Library recommendation:** `expr-eval` (no specific version constraint supplied by guidance; confirm against SCA tooling)

## Explanation

The original code passes untrusted user input directly into the `Function()` constructor, which compiles and executes arbitrary JavaScript. An attacker can inject malicious code such as process termination, system commands, or data exfiltration. The fix replaces dynamic code compilation with `expr-eval`, a dedicated expression parser designed for safe mathematical expression evaluation. The parser only evaluates mathematical expressions and operator chains, rejecting any syntax that attempts to invoke functions, access constructors, or reference unintended scope. The `order` object is passed as an evaluation context variable, giving the expression read-only access to its properties without exposing the global scope.

## Behaviour changes

- `expr-eval` parses and evaluates the expression in a restricted context, accepting only mathematical operations, property access via dot notation, and variables passed in the evaluation context. It rejects code constructs (function calls, `require()`, constructors, etc.).
- The return value is the result of the expression evaluation; the contract remains unchanged.
- No additional network or filesystem side effects are introduced.
- Performance is slightly higher due to parsing overhead, but this is acceptable for a preview operation.
